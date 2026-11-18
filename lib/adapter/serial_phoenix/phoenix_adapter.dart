import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/services.dart';
import 'package:logging/logging.dart';

import '../../utils/hex_utils.dart';
import '../../utils/platform_adapter.dart';
import '../euicc_adapter.dart';
import 'phoenix_link.dart';

/// Reader support for Phoenix / Smartmouse style serial smart card readers.
///
/// These are the cheap RS-232 (often PL2303/CH340 based) readers sold for SIM
/// tooling: the reader only shifts levels, so the ISO 7816 framing, the card
/// reset and the T=0 handshake all happen here.
class PhoenixAdapter extends BaseAdapter {
  static final Logger _logger = Logger('PhoenixAdapter');

  PhoenixAdapter() : super(_logger);

  // ignore: close_sinks
  final StreamController<EuiccPortState> _state =
      StreamController<EuiccPortState>.broadcast();

  PhoenixLink? _link;
  String? _lastAtr;

  @override
  Stream<EuiccPortState> get stateStream => _state.stream;

  @override
  bool get requiresRefresh => true;

  @override
  String? get lastAtr => _lastAtr;

  @override
  Future<List<Reader>> listReaders({bool force = false}) async {
    if (!PlatformX.isWindows) return const [];
    try {
      final ports = PhoenixLink.availablePorts();
      _logger.info('Phoenix: serial ports found: '
          '${ports.isEmpty ? "(none)" : ports.join(", ")}');
      return ports
          .map((port) => Reader(id: 'phoenix:$port', name: port, source: this))
          .toList();
    } catch (e) {
      _logger.warning('Phoenix reader enumeration failed: $e');
      return const [];
    }
  }

  @override
  Future<void> connect(Reader reader) async {
    _logger.info('Opening Phoenix reader ${reader.name}...');
    final link = PhoenixLink.open(reader.name);
    try {
      final atr = await link.reset();
      if (atr.isEmpty || (atr[0] != 0x3B && atr[0] != 0x3F)) {
        throw PhoenixException(
            '${reader.name}: no ATR (card not inserted, or the reader is in '
            'Smartmouse mode instead of Phoenix mode)');
      }
      _link = link;
      _lastAtr = HexUtils.bytesToHex(atr);
      updateConnectedReader(reader);
      _state.add(EuiccPortState.open);
      _logger.info('Phoenix reader ${reader.name} ready, ATR=$_lastAtr');
    } catch (e) {
      _link = null;
      _lastAtr = null;
      link.close();
      _logger.severe('Failed to bring up ${reader.name}: $e');
      rethrow;
    }
  }

  @override
  Future<void> disconnect() async {
    final link = _link;
    _link = null;
    _lastAtr = null;
    currentEid = null;
    updateConnectedReader(null);
    _state.add(EuiccPortState.closed);
    link?.close();
  }

  @override
  Future<Channel> openChannel({List<String>? aids}) {
    return openLogicalChannel(aids: aids);
  }

  @override
  Future<Uint8List> sendRawApdu(Uint8List apdu) async {
    final link = _link;
    if (link == null) {
      throw PlatformException(
        code: 'DISCONNECTED',
        message: 'Phoenix serial reader is not connected',
      );
    }

    var cmd = apdu;
    Object? lastError;
    for (var attempt = 0; attempt < 3; attempt++) {
      Uint8List rsp;
      try {
        rsp = await link.transceive(cmd);
      } catch (e) {
        lastError = e;
        _logger.fine('APDU tx=${HexUtils.bytesToHex(apdu)} -> $e');
        // A silent card usually means it lost its supply or was reset by
        // line noise. Re-run the reset sequence before the next attempt.
        if (attempt < 2) {
          try {
            final atr = await link.reset();
            _logger.fine('Recovery reset, ATR=${HexUtils.bytesToHex(atr)}');
          } catch (_) {
            // keep the original error
          }
        }
        continue;
      }

      _logger.fine(
        'APDU tx=${HexUtils.bytesToHex(apdu)} rx=${HexUtils.bytesToHex(rsp)}',
      );
      if (rsp.length < 2) {
        lastError = 'short response (${rsp.length} bytes)';
        continue;
      }

      final sw1 = rsp[rsp.length - 2];
      final sw2 = rsp[rsp.length - 1];

      // Le rejected: the card tells us the length it wants.
      if (sw1 == 0x6C) {
        cmd = Uint8List.fromList([...apdu.sublist(0, 4), sw2]);
        continue;
      }

      // More data available: chain GET RESPONSE until it is drained.
      if (sw1 == 0x61) {
        var body = rsp.sublist(0, rsp.length - 2);
        var remaining = sw2;
        while (remaining > 0) {
          final more = await link.transceive(
            Uint8List.fromList([0x00, 0xC0, 0x00, 0x00, remaining]),
          );
          if (more.length < 2) break;
          body = Uint8List.fromList(
            [...body, ...more.sublist(0, more.length - 2)],
          );
          remaining = more[more.length - 2] == 0x61 ? more[more.length - 1] : 0;
        }
        return Uint8List.fromList([...body, 0x90, 0x00]);
      }

      return rsp;
    }

    throw PhoenixException(
      'APDU failed after 3 attempts: $lastError '
      '(echoErrors=${link.echoErrors})',
    );
  }
}
