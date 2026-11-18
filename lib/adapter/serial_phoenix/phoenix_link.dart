import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

/// Raised when the Phoenix link cannot complete a card transaction.
class PhoenixException implements Exception {
  final String message;
  PhoenixException(this.message);

  @override
  String toString() => 'PhoenixException: $message';
}

/// Win32 serial port wrapper (COMx, 8E2, manual RTS/DTR).
///
/// The Phoenix reader is a passive level shifter: the card clock and the ISO
/// 7816 framing are produced by this process, and RST is wired to RTS.
class _Win32Serial {
  static final DynamicLibrary _k32 = DynamicLibrary.open('kernel32.dll');

  static final int Function(Pointer<Utf16>, int, int, Pointer<Void>, int, int, int)
      _createFileW = _k32
          .lookupFunction<
              IntPtr Function(Pointer<Utf16>, Uint32, Uint32, Pointer<Void>,
                  Uint32, Uint32, IntPtr),
              int Function(Pointer<Utf16>, int, int, Pointer<Void>, int, int,
                  int)>('CreateFileW');

  static final int Function(int) _closeHandle =
      _k32.lookupFunction<Int32 Function(IntPtr), int Function(int)>(
          'CloseHandle');

  static final int Function(int, Pointer<Uint8>) _setCommState = _k32
      .lookupFunction<Int32 Function(IntPtr, Pointer<Uint8>),
          int Function(int, Pointer<Uint8>)>('SetCommState');

  static final int Function(int, Pointer<Uint8>) _setCommTimeouts = _k32
      .lookupFunction<Int32 Function(IntPtr, Pointer<Uint8>),
          int Function(int, Pointer<Uint8>)>('SetCommTimeouts');

  static final int Function(int, int) _purgeComm =
      _k32.lookupFunction<Int32 Function(IntPtr, Uint32), int Function(int, int)>(
          'PurgeComm');

  static final int Function(int, int) _escapeCommFunction = _k32
      .lookupFunction<Int32 Function(IntPtr, Uint32), int Function(int, int)>(
          'EscapeCommFunction');

  static final int Function(int, Pointer<Uint8>, int, Pointer<Uint32>, Pointer<Void>)
      _readFile = _k32.lookupFunction<
          Int32 Function(IntPtr, Pointer<Uint8>, Uint32, Pointer<Uint32>,
              Pointer<Void>),
          int Function(int, Pointer<Uint8>, int, Pointer<Uint32>,
              Pointer<Void>)>('ReadFile');

  static final int Function(int, Pointer<Uint8>, int, Pointer<Uint32>, Pointer<Void>)
      _writeFile = _k32.lookupFunction<
          Int32 Function(IntPtr, Pointer<Uint8>, Uint32, Pointer<Uint32>,
              Pointer<Void>),
          int Function(int, Pointer<Uint8>, int, Pointer<Uint32>,
              Pointer<Void>)>('WriteFile');

  static final int Function(Pointer<Utf16>, Pointer<Utf16>, int) _queryDosDeviceW =
      _k32.lookupFunction<
          Uint32 Function(Pointer<Utf16>, Pointer<Utf16>, Uint32),
          int Function(Pointer<Utf16>, Pointer<Utf16>, int)>('QueryDosDeviceW');

  static final RegExp _comPattern = RegExp(r'^COM\d+$');

  /// COM ports present on the system, straight from the object-manager
  /// namespace. Unlike an open-probe this also reports ports that another
  /// process currently holds open.
  static List<String> comPorts() {
    const int bufChars = 65536;
    final raw = calloc<Uint16>(bufChars);
    try {
      final len = _queryDosDeviceW(nullptr, raw.cast<Utf16>(), bufChars);
      if (len == 0) return const [];
      final units = raw.asTypedList(len);
      final out = <String>[];
      var start = 0;
      for (var i = 0; i < len; i++) {
        if (units[i] != 0) continue;
        if (i > start) {
          final name = String.fromCharCodes(units, start, i);
          if (_comPattern.hasMatch(name)) out.add(name);
        }
        start = i + 1;
      }
      return out;
    } catch (_) {
      return const [];
    } finally {
      calloc.free(raw);
    }
  }

  static const int _genericRead = 0x80000000;
  static const int _genericWrite = 0x40000000;
  static const int _openExisting = 3;

  static const int _purgeTxClear = 0x0004;
  static const int _purgeRxClear = 0x0008;

  static const int _setRts = 3;
  static const int _clrRts = 4;
  static const int _setDtr = 5;
  static const int _clrDtr = 6;

  final int _handle;
  final Pointer<Uint32> _readCount = calloc<Uint32>();
  final Pointer<Uint32> _writeCount = calloc<Uint32>();
  final Pointer<Uint8> _buf = calloc<Uint8>(512);

  _Win32Serial._(this._handle);

  static _Win32Serial? tryOpen(String portName, {int baud = 19200}) {
    final path = '\\\\.\\$portName'.toNativeUtf16();
    final handle = _createFileW(
      path,
      _genericRead | _genericWrite,
      0,
      nullptr,
      _openExisting,
      0,
      0,
    );
    calloc.free(path);

    if (handle == -1) return null;

    final self = _Win32Serial._(handle);
    if (!self._configure(baud)) {
      self.close();
      return null;
    }
    return self;
  }

  bool _configure(int baud) {
    // DCB is 28 bytes; bitfield flags are written by hand to avoid layout
    // assumptions. fBinary=1, everything else 0 (DTR/RTS driven manually).
    final dcb = calloc<Uint8>(28);
    final bytes = dcb.asTypedList(28);
    final view = ByteData.view(bytes.buffer, bytes.offsetInBytes, 28);
    view.setUint32(0, 28, Endian.little); // DCBlength
    view.setUint32(4, baud, Endian.little); // BaudRate
    view.setUint32(8, 0x00000001, Endian.little); // fBinary
    view.setUint16(12, 0, Endian.little); // wReserved
    view.setUint16(14, 2048, Endian.little); // XonLim
    view.setUint16(16, 512, Endian.little); // XoffLim
    view.setUint8(18, 8); // ByteSize
    view.setUint8(19, 2); // Parity: EVENPARITY
    view.setUint8(20, 2); // StopBits: TWOSTOPBITS
    view.setUint8(21, 0x11); // XonChar
    view.setUint8(22, 0x13); // XoffChar
    view.setUint8(23, 0); // ErrorChar
    view.setUint8(24, 0); // EofChar
    view.setUint8(25, 0); // EvtChar
    view.setUint16(26, 0, Endian.little); // wReserved1

    final ok = _setCommState(_handle, dcb) != 0;
    calloc.free(dcb);
    if (!ok) return false;

    // COMMTIMEOUTS: return as soon as anything is buffered, otherwise wait.
    final to = calloc<Uint8>(20);
    final toBytes = to.asTypedList(20);
    final toView = ByteData.view(toBytes.buffer, toBytes.offsetInBytes, 20);
    toView.setUint32(0, 0xFFFFFFFF, Endian.little); // ReadIntervalTimeout
    toView.setUint32(4, 0, Endian.little); // ReadTotalTimeoutMultiplier
    toView.setUint32(8, 20, Endian.little); // ReadTotalTimeoutConstant
    toView.setUint32(12, 0, Endian.little); // WriteTotalTimeoutMultiplier
    toView.setUint32(16, 500, Endian.little); // WriteTotalTimeoutConstant
    final okTo = _setCommTimeouts(_handle, to) != 0;
    calloc.free(to);
    if (!okTo) return false;

    _purgeComm(_handle, _purgeTxClear | _purgeRxClear);
    return true;
  }

  void setRts(bool on) =>
      _escapeCommFunction(_handle, on ? _setRts : _clrRts);

  void setDtr(bool on) =>
      _escapeCommFunction(_handle, on ? _setDtr : _clrDtr);

  void purgeInput() => _purgeComm(_handle, _purgeRxClear);

  void writeByte(int value) {
    _buf[0] = value;
    _writeFile(_handle, _buf, 1, _writeCount, nullptr);
  }

  /// Reads up to [max] bytes, waiting at most [timeoutMs] for the first one.
  Uint8List read(int max, int timeoutMs) {
    final out = BytesBuilder(copy: false);
    final deadline = DateTime.now().add(Duration(milliseconds: timeoutMs));
    while (out.length < max) {
      if (_readFile(_handle, _buf, max - out.length, _readCount, nullptr) != 0) {
        final n = _readCount.value;
        if (n > 0) {
          out.add(_buf.asTypedList(n).sublist(0, n));
          continue;
        }
      }
      if (DateTime.now().isAfter(deadline)) break;
    }
    return out.toBytes();
  }

  void close() {
    _closeHandle(_handle);
    calloc.free(_readCount);
    calloc.free(_writeCount);
    calloc.free(_buf);
  }
}

/// T=0 transport for a Phoenix/Smartmouse style serial reader.
class PhoenixLink {
  static const int defaultBaud = 19200;

  final _Win32Serial _port;
  int echoErrors = 0;

  PhoenixLink._(this._port);

  /// COM ports that currently exist. Probed by a brief open/close, which does
  /// not touch DTR/RTS, so an attached device is not disturbed.
  static List<String> availablePorts() {
    if (!Platform.isWindows) return const [];

    // Preferred: ask the object manager for the DOS device list. This works
    // even when another process (VMware, a terminal) holds the port open, so
    // the port still shows up and the user gets a clear "cannot open" instead
    // of a silently empty list.
    final named = _Win32Serial.comPorts();
    if (named.isNotEmpty) {
      named.sort((a, b) =>
          int.parse(a.substring(3)).compareTo(int.parse(b.substring(3))));
      return named;
    }

    // Fallback: probe COM1..COM32 by opening each one.
    final found = <String>[];
    for (var i = 1; i <= 32; i++) {
      final name = 'COM$i';
      final probe = _Win32Serial.tryOpen(name);
      if (probe != null) {
        probe.close();
        found.add(name);
      }
    }
    return found;
  }

  static PhoenixLink open(String portName, {int baud = defaultBaud}) {
    final serial = _Win32Serial.tryOpen(portName, baud: baud);
    if (serial == null) {
      throw PhoenixException('cannot open $portName');
    }
    return PhoenixLink._(serial);
  }

  void close() => _port.close();

  Future<void> _delay(int ms) => Future<void>.delayed(Duration(milliseconds: ms));

  /// RTS is wired to RST on a Phoenix reader: assert, release, read the ATR.
  Future<Uint8List> reset() async {
    _port.setRts(false);
    _port.setDtr(false);
    await _delay(120);
    _port.purgeInput();
    _port.setRts(true);
    await _delay(120);
    _port.purgeInput();
    _port.setRts(false);
    await _delay(450);

    final atr = <int>[];
    final deadline = DateTime.now().add(const Duration(milliseconds: 1200));
    while (DateTime.now().isBefore(deadline)) {
      final chunk = _port.read(64, 120);
      if (chunk.isEmpty) {
        if (atr.isNotEmpty) break; // line went quiet: ATR complete
        continue;
      }
      atr.addAll(chunk);
    }
    return Uint8List.fromList(atr);
  }

  /// TX and RX are tied together on the card I/O line, so every transmitted
  /// byte comes back and has to be drained before the card answers.
  Future<void> _txByte(int value) async {
    _port.writeByte(value);
    final echo = _port.read(1, 150);
    if (echo.length != 1 || echo[0] != value) echoErrors++;
  }

  Future<void> _txBytes(Uint8List data) async {
    for (final b in data) {
      await _txByte(b);
    }
  }

  /// First non-NULL byte after a header: either the procedure byte (INS) or
  /// the first byte of the card's answer.
  Future<int> _firstResponseByte() async {
    var b = _port.read(1, 900);
    while (b.isNotEmpty && b[0] == 0x60) {
      b = _port.read(1, 900); // NULL: card is still working
    }
    if (b.isEmpty) {
      throw PhoenixException('no response byte (echoErrors=$echoErrors)');
    }
    return b[0];
  }

  /// One T=0 transaction (ISO 7816-3). Handles case 1/2/3/4.
  Future<Uint8List> transceive(Uint8List apdu) async {
    if (apdu.length < 5) {
      throw PhoenixException('APDU shorter than 5 bytes');
    }
    final ins = apdu[1];
    final p3 = apdu[4];
    final hasData = apdu.length > 5;

    await _txBytes(Uint8List.sublistView(apdu, 0, 5));

    // Case 3/4: the card acknowledges with the INS byte before taking data.
    if (hasData) {
      final pb = await _firstResponseByte();
      if (pb == ins) {
        await _txBytes(Uint8List.sublistView(apdu, 5));
        return _port.read(2, 5000);
      }
      return Uint8List.fromList([pb, ..._port.read(1, 900)]);
    }

    // Case 1/2: no input data. The card either sends Le bytes then SW, or SW
    // straight away -- so the first byte is data, not a procedure byte.
    final first = await _firstResponseByte();
    if (first == ins) {
      final body = _port.read(p3, 5000);
      return Uint8List.fromList([...body, ..._port.read(2, 2000)]);
    }
    if (p3 == 0) {
      return Uint8List.fromList([first, ..._port.read(1, 900)]);
    }
    final body = Uint8List.fromList([first, ..._port.read(p3 - 1, 5000)]);
    return Uint8List.fromList([...body, ..._port.read(2, 2000)]);
  }
}
