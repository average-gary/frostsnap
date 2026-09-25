// The real desktop app driven against cold-snap virtual devices on pseudo-terminals.
//
// WHAT RUNS HERE is the shipping Rust: `UsbSerialManager`'s port state machine, the real
// `FrostCoordinator`, the real naming/keygen/address/send/signing paths, the real
// `frostsnap_core` signer on the device side. Two things are substituted and both say so
// in their names: the TRANSPORT (`Api.loadTestPtySerial`, which enumerates the rig's ptys
// and refuses anything else) and the CHAIN (`SuperWallet.testInjectFunding`, which
// delivers a coin through the same `apply_update` a finished Electrum sync uses, because
// this machine has no Electrum server). Consent is NOT substituted: every screen is
// answered by a separate cold-snap OS process that read the randomised confirm digit back
// out of its own framebuffer, and `WireSignTask::Test` is never used.
//
// Launch, one command, from cold-snap:
//
//     tools/app-rig-test.sh
//
// which is `tools/app-rig.py` (N ptys, one firmware process each) wrapping this file. By
// hand, with the pinned SDK on PATH:
//
//     cd "$HOME/repos/cold-snap" && python3 tools/app-rig.py --devices 4 \
//       --decline-signing 2 -- /bin/sh -c 'cd "$HOME/repos/frostsnap/frostsnapp" && \
//       BUNDLE_FIRMWARE=0 flutter test integration_test/coldsnap_workflows_test.dart -d macos'
//
// WITHOUT THE RIG THIS FILE FAILS rather than skipping: an unset
// `FROSTSNAP_TEST_SERIAL_PORTS` is a missing rig, and a check that passes by not running
// is not a check.
//
// A device restored by consolidating a typed backup then SIGNS through this app, and its
// first reply is lost on the wire (`--lose-first-share`, a rig fault injection) so the
// replug + re-sent request drives the core's at-most-once rule end to end.
//
// THE APP IS RESTARTED: this file runs as two app processes (`COLDSNAP_RIG_APP_RUN` 1, 2;
// `tools/app-rig.py --app-restart`) over one app dir while the stubs stay up. Run 2
// reloads the wallet from sqlite/bdk, checks it against what run 1 recorded, and signs
// with it. A stub PROCESS restart is not covered: FakeFlash lives in memory.
//
// WHAT IT DOES NOT COVER, because no software rig can: USB enumeration and the OTG_FS
// register sequences, SSD1306 init/timing and physical legibility, keypad scan/debounce
// and its randomised timing, the callgate, the TRNG's two sources, panic/reset recovery,
// real STM32 program/erase and power-loss durability, and FROST signing latency on a
// 120 MHz M4F. It exercises `comms.rs` fully and `usb.rs` not at all.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import 'package:frostsnap/device.dart' show dropErasedDeviceShares;
import 'package:frostsnap/id_ext.dart';
import 'package:frostsnap/src/rust/api.dart';
import 'package:frostsnap/src/rust/api/backup_run.dart';
import 'package:frostsnap/src/rust/api/bitcoin.dart';
import 'package:frostsnap/src/rust/api/coordinator.dart';
import 'package:frostsnap/src/rust/api/device_list.dart';
import 'package:frostsnap/src/rust/api/keygen.dart';
import 'package:frostsnap/src/rust/api/nonce_replenish.dart';
import 'package:frostsnap/src/rust/api/recovery.dart';
import 'package:frostsnap/src/rust/api/signing.dart';
import 'package:frostsnap/src/rust/api/super_wallet.dart';
import 'package:frostsnap/src/rust/api/transaction.dart';
import 'package:frostsnap/src/rust/frb_generated.dart';
import 'package:frostsnap/src/rust/lib.dart';

/// Regtest throughout: the only network whose coins are worthless by construction.
const network = BitcoinNetwork.regtest;

/// 2-of-3, well inside the declared support envelope (n <= 12, any t <= n).
const threshold = 2;

/// What the funding coin is worth, and what we pay away from it. Both far above the dust
/// bound and far below anything, so the fee is the only thing coin selection has to think
/// about.
const fundingSats = 5000000; // 0.05 BTC
const sendSats = 1234567;
const feerate = 4.0; // sat/vB, CUSTOM: fee estimation needs an Electrum server.

/// A FIXED key, not the platform keychain's. `DesktopSecureKeyProvider` reaches macOS
/// keychain services, which a headless test process should not; this wallet is disposable
/// and its whole database is deleted with the rig directory.
final encryptionKey = SymmetricKey(
  field0: U8Array32(Uint8List.fromList(List.filled(32, 0x2b))),
);

String requireEnv(String name) {
  final value = Platform.environment[name];
  if (value == null || value.isEmpty) {
    throw StateError(
      '$name is not set. This test has to run under cold-snap\'s tools/app-rig.py, '
      'which creates the ptys, launches one firmware session per device and exports '
      'this variable. Running it bare would test nothing.',
    );
  }
  return value;
}

late final String manifestPath = requireEnv('FROSTSNAP_TEST_SERIAL_PORTS');
late final String rigDir = requireEnv('COLDSNAP_RIG_DIR');
late final String coldsnapRepo = requireEnv('COLDSNAP_REPO');

/// WHICH APP PROCESS THIS IS. `tools/app-rig.py --app-restart` runs this file twice against
/// the same stubs and the same app dir: run `1` starts from an empty app dir and does the
/// keygen, signing, restoration and replug workflows; its whole process group is reaped;
/// run `2` is a NEW app process that loads what run 1 persisted (sqlite + bdk), checks it
/// against [restartSnapshotPath], signs with it, and then does the destructive erase
/// workflows. The stubs are not restarted: their FakeFlash is in memory.
late final String appRun = requireEnv('COLDSNAP_RIG_APP_RUN');

/// Written by run 1 just before it exits, countersigned (`reloadedByPid`) by run 2 once the
/// reloaded wallet has signed; `tools/app-rig.py` exits 6 without the countersignature.
late final String restartSnapshotPath = '$rigDir/app-restart.json';

/// Run one of cold-snap's rig tools and insist it succeeded.
///
/// ASYNC AND BOUNDED, never `Process.runSync`: a synchronous call blocks this isolate, so
/// a hung tool would also stop every per-test `Timeout(...)` from firing, leaving only the
/// rig's whole-run bound. `regtest.py` bounds each of its own waits; [limit] is the
/// backstop above those. On expiry the tool is killed and the failure is named; a node it
/// may have left is stopped by `tools/app-rig.py`'s teardown (`regtest.py down` on this
/// run's own datadir).
Future<String> coldsnapTool(
  String tool,
  List<String> args, {
  int expect = 0,
  Duration limit = const Duration(minutes: 4),
}) async {
  final proc = await Process.start('python3', ['$coldsnapRepo/tools/$tool', ...args]);
  final stdout = proc.stdout.transform(utf8.decoder).join();
  final stderr = proc.stderr.transform(utf8.decoder).join();
  final int code;
  try {
    code = await proc.exitCode.timeout(limit);
  } on TimeoutException {
    proc.kill(ProcessSignal.sigterm);
    await proc.exitCode
        .timeout(const Duration(seconds: 10), onTimeout: () {
      proc.kill(ProcessSignal.sigkill);
      return -1;
    });
    throw StateError(
      'TIMEOUT: $tool ${args.join(' ')} did not exit in ${limit.inSeconds}s; killed\n'
      'stderr: ${await stderr.timeout(const Duration(seconds: 5), onTimeout: () => '')}',
    );
  }
  final out = await stdout;
  final err = (await stderr).trim();
  if (code != expect) {
    throw StateError(
      '$tool ${args.join(' ')} exited $code, expected $expect\n'
      'stdout: $out\nstderr: $err',
    );
  }
  // Echoed, not swallowed: `regtest.py` says ACCEPTED/REJECTED on stderr, and that line is
  // the whole point of the second opinion -- an exit code alone leaves a reader taking this
  // file's word for which transaction Bitcoin Core judged.
  if (err.isNotEmpty) print('$tool ${args.first}: $err');
  return out.trim();
}

/// The `DeviceId`s the rig launched, in rig-device order, taken off the file the launcher
/// wrote after it checked they were distinct. The app must see exactly these.
List<String> rigIdentities() => File('$rigDir/identities.tsv')
    .readAsLinesSync()
    .where((line) => line.contains('\t'))
    .map(
      (line) => RegExp(r'DeviceId\(([0-9a-f]+)\)').firstMatch(line)!.group(1)!,
    )
    .toList();

/// One rig device's stderr: every line it printed, including the `glass page N row M`
/// lines that are the rendered pixels of the screens it consented to.
String deviceLog(int rigIndex) =>
    File('$rigDir/device-$rigIndex.log').readAsStringSync();

/// The rendered screen rows this device drew, newest last. THE PIXELS, not the
/// coordinator's copy of the request: `firmware/examples/stub.rs::log_glass` reads each
/// cell back through the shipped reverse glyph lookup.
List<String> glassRows(int rigIndex) => deviceLog(rigIndex)
    .split('\n')
    .where((line) => line.contains('stub: glass page '))
    .map((line) => line.substring(line.indexOf(': ', line.indexOf('row ')) + 2))
    .toList();

/// Let go of a coordinator protocol stream the way the app's screens do.
///
/// `await sub.cancel()` HANGS on a protocol that never completes -- and address
/// verification is exactly that: `VerifyAddressProtocol` has no terminal state, because
/// the human decides when they have compared the two strings. The app's own seam is
/// `cancelProtocol()`, so that is what this uses, and the `cancel()` is deliberately
/// un-awaited: waiting on a sink Rust has not closed is the hang, not the fix.
void letGo(StreamSubscription<dynamic> sub, {bool cancelProtocol = false}) {
  if (cancelProtocol) coordinatorForCleanup!.cancelProtocol();
  sub.cancel();
}

/// Set once in `setUpAll`, for [letGo] -- which cannot take it as a parameter without
/// every call site repeating it.
Coordinator? coordinatorForCleanup;

/// Poll until `check` returns non-null. Named, so a timeout says which workflow stalled
/// rather than just failing.
Future<T> until<T>(
  String what,
  T? Function() check, {
  Duration timeout = const Duration(seconds: 90),
}) async {
  final deadline = DateTime.now().add(timeout);
  var attempts = 0;
  while (DateTime.now().isBefore(deadline)) {
    final got = check();
    if (got != null) return got;
    attempts++;
    await Future.delayed(const Duration(milliseconds: 100));
  }
  throw StateError(
    'TIMEOUT after ${timeout.inSeconds}s and $attempts polls waiting for: $what',
  );
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  if (appRun != '1' && appRun != '2') {
    throw StateError('COLDSNAP_RIG_APP_RUN is "$appRun"; want 1 or 2');
  }

  /// A test that runs only in the given app process (see [appRun]).
  void inRun(
    String run,
    Object description,
    dynamic Function() body, {
    Timeout? timeout,
  }) {
    if (appRun == run) test(description, body, timeout: timeout);
  }

  void firstApp(Object d, dynamic Function() b, {Timeout? timeout}) =>
      inRun('1', d, b, timeout: timeout);
  void secondApp(Object d, dynamic Function() b, {Timeout? timeout}) =>
      inRun('2', d, b, timeout: timeout);

  late Api api;
  late Coordinator coord;
  late SuperWallet wallet;

  /// Rig index -> the app's view of that device. Filled by the first test.
  final byRigIndex = <int, ConnectedDevice>{};
  late Set<int> declineSigning;

  // Carried between tests, in order, because these are the stages of one workflow and
  // re-running a keygen per stage would be testing a different thing.
  AccessStructureRef? asRef;
  MasterAppkey? masterAppkey;
  String? signedTxHex;

  DeviceId idOf(int rigIndex) => byRigIndex[rigIndex]!.id;

  /// Ask each device for its signature share, but only once the signing dispatcher has
  /// SEEN it connected.
  ///
  /// `SigningDispatcher::send_sign_request` drops the request on the floor unless the
  /// device is in its `connected_but_need_request` set, and that set is filled by the
  /// dispatcher's own `connected()` callback after the session opens. Requesting too
  /// early is silent: no error, no frame, and a session that waits forever. The set is
  /// checked across every state seen rather than the latest one, because the device is
  /// removed from it the moment the request goes out.
  Future<void> requestSharesFrom(
    List<DeviceId> devices,
    List<SigningState> states,
    SignSessionId sessionId,
  ) async {
    for (final id in devices) {
      await until<bool>(
        'the signing dispatcher to see ${id.toHex()} connected',
        () =>
            states.any(
              (state) => state.connectedButNeedRequest.any(
                (d) => d.toHex() == id.toHex(),
              ),
            )
            ? true
            : null,
      );
      coord.requestDeviceSign(
        deviceId: id,
        sessionId: sessionId,
        encryptionKey: encryptionKey,
      );
    }
  }

  setUpAll(() async {
    declineSigning = requireEnv(
      'COLDSNAP_RIG_DECLINE_SIGNING',
    ).split(',').where((s) => s.isNotEmpty).map(int.parse).toSet();
    await RustLib.init();
    api = Api();
    // A DISPOSABLE app directory under the rig's own ignored output dir. Both the
    // coordinator's sqlite DB and the bdk wallet files derive from it, so nothing here
    // can reach the real `getApplicationSupportDirectory()` wallet.
    final appDir = Directory('$rigDir/app-dir');
    if (appRun == '1') {
      if (appDir.existsSync()) appDir.deleteSync(recursive: true);
      appDir.createSync(recursive: true);
      final stale = File(restartSnapshotPath);
      if (stale.existsSync()) stale.deleteSync();
    } else {
      // THE RESTART: the same directory, read back, never wiped or recreated. An empty one
      // means run 1 persisted nothing, and loading it would be a fresh wallet.
      if (!appDir.existsSync() || appDir.listSync().isEmpty) {
        throw StateError('RESTART: ${appDir.path} is missing or empty');
      }
      if (!File(restartSnapshotPath).existsSync()) {
        throw StateError('RESTART: run 1 left no $restartSnapshotPath');
      }
    }
    final (coord_, appCtx) = await api.loadTestPtySerial(
      appDir: appDir.path,
      portManifest: manifestPath,
    );
    coord = coord_;
    coordinatorForCleanup = coord;
    wallet = appCtx.settings.getSuperWallet(network: network);
    coord.startThread();
    // Corroboration only, and it is started here rather than asserted on: the pass
    // criterion is the fixture plus the independent sighash recomputation. Once, in run 1:
    // the node outlives the app restart like the stubs do, so run 2's spend of run 1's
    // funding coin can still be judged by Core.
    if (appRun == '1') await coldsnapTool('regtest.py', ['up']);
  });

  tearDownAll(() async {
    // Never leave a node or a datadir behind. `tools/app-rig.py`'s teardown runs the same
    // command on the same datadir (`COLDSNAP_REGTEST_DATADIR`) for the runs that never
    // reach here.
    // Run 1 leaves it up for run 2; if run 2 never starts, the rig's teardown stops it.
    if (appRun == '2') await coldsnapTool('regtest.py', ['down']);
  });

  test(
    'every rig device announces as a recognized, compatible Mk4',
    () async {
      final expected = rigIdentities();
      expect(
        expected.length,
        greaterThanOrEqualTo(4),
        reason: 'this file needs 3 wallet devices and 1 blank one',
      );

      final devices = await until<List<ConnectedDevice>>(
        '${expected.length} devices to announce over their own ptys',
        () {
          final state = coord.deviceListState();
          return state.devices.length >= expected.length ? state.devices : null;
        },
      );

      // ACROSS PROCESSES: the ids the launcher recorded are the ids the coordinator sees.
      // Two children at one entropy salt would collide here, and the app would show one
      // device where the rig launched four.
      final seen = {for (final d in devices) d.id.toHex(): d};
      expect(
        seen.length,
        devices.length,
        reason: 'two ports announced one DeviceId',
      );
      for (var i = 0; i < expected.length; i++) {
        expect(
          seen.keys,
          contains(expected[i]),
          reason:
              'rig device $i (${expected[i]}) never reached the coordinator',
        );
        byRigIndex[i] = seen[expected[i]]!;
      }

      for (final device in devices) {
        // The announced digest is task 01's packaged, key-0-signed artifact, whose
        // `firmware_digest` is the sole entry in `coldsnap-mk4-registry.txt`. With the
        // stub's own synthetic digest instead, every one of these is `Unrecognized` --
        // `is_compatible() == false`, every capability false -- and the app refuses the
        // keygen. That refusal is correct; it is why the rig passes `STUB_IMAGE`.
        expect(
          device.isCompatible(),
          isTrue,
          reason:
              'device ${device.id.toHex()} announced firmware the app does not '
              'recognize (${device.firmwareName()})',
        );
        expect(device.firmwareName(), startsWith('mk4 '));
        expect(
          device.capabilities().maxKeygenDevices,
          12,
          reason: 'the declared keygen ceiling is a capability of the firmware',
        );
        // A cold-snap device asks on its own glass before erasing (task 08) and
        // refuses every upgrade message on the wire.
        expect(device.capabilities().erase, isTrue);
        expect(device.capabilities().updateMode, isFalse);
        expect(device.capabilities().backup, isTrue);
      }
    },
    timeout: const Timeout(Duration(minutes: 3)),
  );

  firstApp(
    'naming and a 2-of-3 keygen through the app\'s own APIs',
    () async {
      final wallet3 = [idOf(0), idOf(1), idOf(2)];
      final names = {
        for (var i = 0; i < wallet3.length; i++) wallet3[i]: 'rig-device-$i',
      };
      // PREVIEW THEN COMMIT, which is the app's own two-step: `updateNamePreview` puts the
      // name on the device's glass, and `finalizeKeygen` commits it.
      for (final entry in names.entries) {
        await coord.updateNamePreview(id: entry.key, name: entry.value);
      }

      // NONCES FIRST, which is `wallet_create.dart`'s own order: a device supplies its
      // nonce stream before it can be asked for a signature share, and without this
      // `start_signing` fails with "coordinator doesn't have enough nonces".
      final nonceStates = <NonceReplenishState>[];
      final nonceRequest = coord.createNonceRequest(devices: wallet3);
      expect(
        nonceRequest.someNoncesRequested(),
        isTrue,
        reason:
            'a freshly keygenned device holds no nonces for the coordinator',
      );
      final nonceSub = coord
          .replenishNonces(nonceRequest: nonceRequest, devices: wallet3)
          .listen(nonceStates.add);
      try {
        await until<bool>('all 3 devices to hand over a nonce stream', () {
          final last = nonceStates.isEmpty ? null : nonceStates.last;
          if (last?.abort ?? false) throw StateError('nonce replenish ABORTED');
          return (last?.isFinished() ?? false) ? true : null;
        });
      } finally {
        letGo(nonceSub);
      }
      for (final id in wallet3) {
        expect(
          coord.noncesAvailable(id: id),
          greaterThan(0),
          reason: 'device $id gave the coordinator no nonces',
        );
      }

      final states = <KeyGenState>[];
      final stream = coord.generateNewKey(
        threshold: threshold,
        devices: wallet3,
        keyName: 'coldsnap rig',
        network: network,
      );
      final sub = stream.listen(states.add);
      try {
        final ready = await until<KeyGenState>(
          'all 3 devices to acknowledge the session hash off their own glass',
          () {
            final last = states.isEmpty ? null : states.last;
            if (last?.aborted != null) {
              throw StateError('keygen ABORTED: ${last!.aborted}');
            }
            return (last != null && last.allAcks && last.sessionHash != null)
                ? last
                : null;
          },
        );
        expect(ready.gotShares.length, 3);
        expect(ready.sessionAcks.length, 3);

        asRef = await coord.finalizeKeygen(
          keygenId: ready.keygenId,
          encryptionKey: encryptionKey,
          deviceNames: [
            for (final e in names.entries)
              DeviceNameCommit(id: e.key, name: e.value),
          ],
        );
      } finally {
        letGo(sub);
      }

      final access = coord.getAccessStructure(asRef: asRef!)!;
      expect(access.threshold(), threshold);
      expect(access.devices().length, 3);
      masterAppkey = access.masterAppkey();

      // The name reached the device and came back: `getDeviceName` is the coordinator's
      // record, and the device's own `SetName` is what filled it.
      for (final entry in names.entries) {
        expect(coord.getDeviceName(id: entry.key), entry.value);
      }
      // The BLANK device is in no access structure, which is what makes it a restoration
      // target later.
      expect(coord.accessStructuresInvolvingDevice(deviceId: idOf(3)), isEmpty);
    },
    timeout: const Timeout(Duration(minutes: 3)),
  );

  firstApp(
    'the address on the device\'s glass is the one the app handed out',
    () async {
      final info = wallet.nextAddress(masterAppkey: masterAppkey!);
      final address = info.address.toString();
      final before = {for (var i = 0; i < 3; i++) i: glassRows(i).length};

      final sub = coord
          .verifyAddress(keyId: masterAppkey!.keyId(), addressIndex: info.index)
          .listen((_) {});
      try {
        // Every participating device draws it. One is enough to prove the rendering path,
        // but all three are checked because a device drawing somebody else's address is
        // exactly the failure this screen exists to catch.
        for (var i = 0; i < 3; i++) {
          await until<
            bool
          >('device $i to draw address $address on its glass', () {
            final rows = glassRows(i).skip(before[i]!).join(' ');
            // The address is split across rows by `ui::address_verify`, so compare on
            // the concatenation with the spacing removed.
            return rows.replaceAll(' ', '').contains(address) ? true : null;
          });
        }
      } finally {
        letGo(sub, cancelProtocol: true);
      }
      // And it is a screen that authorises NOTHING: no confirm digit, so no `Press (n)`
      // legend. The stub dies if `prompt_screen_at` ever returns a `Page` for it.
      final rows = glassRows(0).skip(before[0]!).join('\n');
      expect(
        rows,
        isNot(contains('Press (')),
        reason: 'an address screen that advertises a consent key is a hole',
      );
    },
    timeout: const Timeout(Duration(minutes: 3)),
  );

  firstApp(
    'a real transaction is built, signed at the glass, and verifies',
    () async {
      // A REAL regtest coin: `regtest.py fund` pays our address and confirms it, so Core
      // holds the prevout the spend will name. Injected through the same
      // `CoordSuperWallet::apply_update` a finished Electrum sync uses.
      final ours = wallet.nextAddress(masterAppkey: masterAppkey!);
      final fundingHex = await coldsnapTool('regtest.py', [
        'fund',
        ours.address.toString(),
        (fundingSats / 100000000).toStringAsFixed(8),
      ]);
      wallet.testInjectFunding(
        masterAppkey: masterAppkey!,
        value: fundingSats,
        fundingTxHex: fundingHex,
      );
      expect(wallet.utxoCount(masterAppkey: masterAppkey!), greaterThan(0));

      // THE APP'S OWN SEND FLOW: `buildTx` -> recipient -> `tryFinish` -> `commitSend`.
      // A CUSTOM feerate, because `refreshConfirmationEstimates` needs a live Electrum
      // server and there is none here -- the fee is then a number this test chose, which
      // is a recorded limitation and not a bypass of anything.
      final foreign = await coldsnapTool('regtest.py', ['newaddress']);
      final build = wallet.buildTx(coord: coord, masterAppkey: masterAppkey!)!;
      build.setConfirmationTarget(
        target: const ConfirmationTarget.custom(feerate),
      );
      // Throws if the node handed us something the app will not pay.
      build.setRecipientWithUri(recipient: 0, uri: foreign);
      build.setAmount(recipient: 0, amount: sendSats);
      final plan = build.tryFinish();
      final inputCount = plan.inputCount();
      final unsigned = wallet.commitSend(coord: coord, plan: plan);
      expect(unsigned.canBroadcast(), isTrue);

      final effect = unsigned.effect();
      expect(effect.foreignOutputs.length, 1);
      expect(effect.foreignOutputs.first.amount, sendSats);
      final fee = effect.fee;

      // WireSignTask::BitcoinTransaction -- `startSigningTx`, never `startSigning`.
      final signers = [idOf(0), idOf(1)];
      final before = {
        for (final i in [0, 1]) i: glassRows(i).length,
      };
      final states = <SigningState>[];
      final sub = coord
          .startSigningTx(
            accessStructureRef: asRef!,
            unsignedTx: unsigned,
            devices: signers,
          )
          .listen(states.add);
      try {
        final session = await until<SigningState>(
          'the signing session to open',
          () => states.isEmpty ? null : states.last,
        );
        await requestSharesFrom(signers, states, session.sessionId);
        final done = await until<SigningState>(
          '$threshold signature shares, each approved at a device\'s own glass',
          () {
            final last = states.last;
            if (last.aborted != null) {
              throw StateError('signing ABORTED: ${last.aborted}');
            }
            // `finishedSignatures != null`, NOT "the stream went quiet": a stream that
            // never emitted also looks done.
            return last.finishedSignatures != null ? last : null;
          },
        );
        expect(done.gotShares.length, threshold);

        // THE DISPLAYED TRANSACTION IS THE ONE BEING SIGNED, read off the pixels each
        // device consented to -- not off the coordinator's copy of the request.
        for (final i in [0, 1]) {
          final shown = glassRows(i).skip(before[i]!).join('\n');
          // ALL whitespace, not just spaces: `ui::SignPages` breaks an address across
          // three rows, so the string only reappears once the row boundaries are gone.
          final flat = shown.replaceAll(RegExp(r'\s'), '');
          expect(
            flat,
            contains(foreign),
            reason:
                'device $i signed without the recipient on its glass:\n$shown',
          );
          // Rendered in satoshis, which is what the device prints.
          expect(
            flat,
            contains('$sendSats'),
            reason: 'device $i signed without the amount on its glass:\n$shown',
          );
          expect(
            flat,
            contains('$fee'),
            reason: 'device $i signed without the fee on its glass:\n$shown',
          );
          expect(
            shown,
            contains('Press ('),
            reason: 'device $i signed a screen that advertised no confirm key',
          );
        }

        final signed = await unsigned.withSignatures(
          signatures: done.finishedSignatures!,
        );
        // INDEPENDENT OF THE SIGNER: BIP-341 sighashes recomputed from the finalised
        // transaction's own bytes and the prevouts, checked with `secp256k1::verify_schnorr`.
        // The coordinator reporting success is not evidence; this is.
        expect(
          wallet.verifyTaprootSignatures(tx: signed),
          inputCount,
          reason: 'every input must have a key-path signature that verifies',
        );
        signedTxHex = wallet.testTxHex(tx: signed);

        // CORROBORATION, and only that: Bitcoin Core runs its own consensus signature
        // check over the same bytes. `testmempoolaccept` relays nothing.
        await coldsnapTool('regtest.py', ['accept', signedTxHex!]);
        // And the mutation that must fail: one satoshi moved off the recipient after
        // signing. Both checkers have to refuse it, or neither is checking the signature.
        final tampered = signedTxHex!.replaceFirst(
          _le64(sendSats),
          _le64(sendSats - 1),
        );
        expect(
          tampered,
          isNot(signedTxHex),
          reason:
              'the recipient value was not found in the serialized transaction',
        );
        // The in-house verifier, over the hex path: first the untampered bytes, so a
        // refusal below cannot be a parse or prevout-lookup failure...
        expect(
          wallet.verifyTaprootSignaturesHex(txHex: signedTxHex!),
          inputCount,
          reason: 'the hex path must verify the transaction the app signed',
        );
        // ...then the mutation, which must fail on the SIGNATURE, not anywhere earlier.
        expect(
          () => wallet.verifyTaprootSignaturesHex(txHex: tampered),
          throwsA(
            predicate(
              (e) => '$e'.contains(
                'signature does not verify against the recomputed sighash',
              ),
            ),
          ),
          reason: 'the in-house verifier accepted a tampered transaction',
        );
        await coldsnapTool('regtest.py', ['accept', tampered], expect: 3);

        expect(fee, greaterThan(0));
      } finally {
        letGo(sub);
      }
    },
    timeout: const Timeout(Duration(minutes: 5)),
  );

  firstApp(
    'a declined signing request yields no share at all',
    () async {
      final decliner = declineSigning.first;
      expect(
        decliner,
        lessThan(3),
        reason:
            'the declining device has to hold a share for this to mean anything',
      );
      final approver = [0, 1, 2].firstWhere((i) => !declineSigning.contains(i));

      // A second, independent transaction, so nothing here can be confused with the
      // session above.
      final foreign = await coldsnapTool('regtest.py', ['newaddress']);
      final build = wallet.buildTx(coord: coord, masterAppkey: masterAppkey!)!;
      build.setConfirmationTarget(
        target: const ConfirmationTarget.custom(feerate),
      );
      build.setRecipientWithUri(recipient: 0, uri: foreign);
      build.setAmount(recipient: 0, amount: sendSats ~/ 2);
      final unsigned = wallet.commitSend(coord: coord, plan: build.tryFinish());

      final states = <SigningState>[];
      final sub = coord
          .startSigningTx(
            accessStructureRef: asRef!,
            unsignedTx: unsigned,
            devices: [idOf(approver), idOf(decliner)],
          )
          .listen(states.add);
      try {
        final session = await until<SigningState>(
          'the signing session to open',
          () => states.isEmpty ? null : states.last,
        );
        final declinedBefore = _countDeclines(decliner);
        await requestSharesFrom(
          [idOf(approver), idOf(decliner)],
          states,
          session.sessionId,
        );
        // The device pressed `x` -- a literal key, and `x` is not in `CONFIRM_CHARSET`,
        // so it refuses whatever digit the screen drew. The protocol has NO message for a
        // no, so what the app sees is silence; the device's own log is the only place the
        // refusal is stated.
        await until<bool>(
          'device $decliner to refuse at its glass',
          () => _countDeclines(decliner) > declinedBefore ? true : null,
        );
        await until<bool>(
          'device $approver\'s share to arrive',
          () => states.last.gotShares.length >= 1 ? true : null,
        );
        // And then it stays at one: 5 s is `DesktopSerial`'s read timeout, so a device
        // that was going to answer has had a full timeout to do it.
        await Future.delayed(const Duration(seconds: 8));
        expect(
          states.last.gotShares.length,
          1,
          reason: 'a declined request produced a share',
        );
        expect(
          states.last.finishedSignatures,
          isNull,
          reason: 'A DECLINED PROMPT PRODUCED A SIGNATURE',
        );
        coord.cancelSignSession(ssid: session.sessionId);
      } finally {
        letGo(sub);
      }
    },
    timeout: const Timeout(Duration(minutes: 4)),
  );

  firstApp(
    'the blank device takes a backup off another device\'s glass',
    () async {
      final source = idOf(0);
      final access = coord.getAccessStructure(asRef: asRef!)!;
      final shareIndex = access.getDeviceShortShareIndex(deviceId: source)!;

      // M7b. The reveal: 25 words drawn on the source device's own glass, walked page by
      // page and written to the sheet a human would carry. With one session per process
      // that sheet has to leave the process, so the stub writes it to the rig's
      // `sheets/` directory -- see `STUB_SHEET_DIR`.
      final sheets = Directory('$rigDir/sheets');
      // SUBSCRIBE FIRST: `markBackupComplete` emits on the key's backup stream and fails
      // with "no backup stream found for key" if nobody is listening -- the app's own
      // backup screen subscribes before it offers the button.
      final runs = <BackupRun>[];
      final runSub = coord
          .backupStream(keyId: masterAppkey!.keyId())
          .listen(runs.add);
      final backupSub = coord
          .displayBackup(
            id: source,
            accessStructureRef: asRef!,
            encryptionKey: encryptionKey,
          )
          .listen((_) {});
      try {
        await until<bool>(
          'device 0 to walk its reveal pages and write the sheet',
          () =>
              sheets.existsSync() && sheets.listSync().isNotEmpty ? true : null,
        );
      } finally {
        letGo(backupSub, cancelProtocol: true);
      }
      await coord.markBackupComplete(
        accessStructureRef: asRef!,
        shareIndex: shareIndex,
      );
      expect(
        coord.getBackupRun(keyId: masterAppkey!.keyId()).devices,
        isNotEmpty,
      );
      await until<bool>(
        'the backup run to record device 0 as complete',
        () =>
            runs.any(
              (run) => run.devices.any(
                (d) => d.shareIndex == shareIndex && d.complete == true,
              ),
            )
            ? true
            : null,
      );
      letGo(runSub);

      // M7c. The quiz, answered only from what that reveal drew -- three candidate words
      // per question, and the device sits by itself deciding. The COORDINATOR reports the
      // verdict, so this is not read off the device's own log.
      final quizStates = <CheckBackupState>[];
      final quizSub = coord
          .tellDeviceToCheckBackup(
            deviceId: source,
            accessStructureRef: asRef!,
            shareIndex: access.getDeviceShareIndex(deviceId: source)!,
            encryptionKey: encryptionKey,
          )
          .listen(quizStates.add);
      try {
        // THE EVENT IS THE VERDICT ON THIS PATH, and `backupManuallyEnteredValid` is not:
        // `CheckBackupProtocol`'s MODERN arm sends `None` for it and only reaches the sink
        // at all on a `CommsMisc::BackupChecked` whose access structure ref AND share index
        // match what was asked -- i.e. the device says it checked the right share of the
        // right wallet. The bool belongs to the LEGACY arm, where the human retypes 25
        // words and the coordinator compares share images; a recognized Mk4 never takes it
        // (`DeviceProfile::needs_legacy_check_backup` is false).
        await until<bool>(
          'device 0 to report it checked the right share of this wallet',
          () => quizStates.isEmpty ? null : true,
        );
        expect(
          quizStates.first.backupManuallyEnteredValid,
          isNull,
          reason:
              'a modern check-backup carries no coordinator-side verdict; if this '
              'ever becomes non-null the device took the legacy 25-word path',
        );
      } finally {
        letGo(quizSub, cancelProtocol: true);
      }
      // And it answered at its own glass, on the randomised digit, like every other screen.
      expect(deviceLog(0), contains('Check -> approved'));
    },
    timeout: const Timeout(Duration(minutes: 5)),
  );
  firstApp('the blank device is restored from that backup and signs with it, '
      'at most once across a lost reply and a replug', () async {
    final blank = idOf(3);
    final source = idOf(0);
    // The rig must have armed the lost-reply fault on THIS device, or the re-send below
    // drives nothing. A missing rig flag is a failure, not a skip.
    expect(
      requireEnv('COLDSNAP_RIG_LOSE_FIRST_SHARE').split(','),
      contains('3'),
      reason:
          'run under tools/app-rig-test.sh, which passes --lose-first-share 3',
    );

    // THE APP'S OWN ORDER (`recovery_flow.dart`: EnterDeviceName before EnterBackup):
    // `DeviceNameField` previews the name on the device, and the device commits it only
    // once the consolidation it consented to has been stored.
    await coord.updateNamePreview(id: blank, name: 'restored-3');

    // M7d. THE LETTER PICKER: the blank device types 25 words back in, one letter at a
    // time, and every one of them comes off the sheet device 0's reveal drew -- read
    // from the rig's `sheets/` directory, because the two devices are separate
    // processes. Nothing asks `Session` which letter comes next.
    final entered = <EnterPhysicalBackupState>[];
    final enterSub = coord
        .tellDeviceToEnterPhysicalBackup(deviceId: blank)
        .listen(entered.add);
    PhysicalBackupPhase phase;
    try {
      phase = await until<PhysicalBackupPhase>(
        'device 3 to type all 25 words back in through the letter picker',
        () {
          final last = entered.isEmpty ? null : entered.last;
          if (last?.abort != null) {
            throw StateError('enter-physical-backup ABORTED: ${last!.abort}');
          }
          return last?.entered;
        },
      );
    } finally {
      // NO `cancelProtocol()` HERE, and that is not tidiness. `CoordinatorSendBody::Cancel`
      // clears `tmp_loaded_backups` on the device -- the whole point of a cancelled
      // ceremony is that it acks nothing -- so cancelling between the entry and the
      // consolidation throws the typed share away and the consolidate then fails with
      // `InvalidMessage { kind: "Consolidate", reason: "we can't consolidate a share we
      // don't know about" }`. MEASURED, exit 2 on the device. The app does not cancel
      // here either.
      letGo(enterSub);
    }
    // Its own log states how it got there: 25 words read off ANOTHER device's sheet and
    // entered one letter at a time through the picker. `Session` was never asked which
    // letter comes next.
    expect(
      deviceLog(3),
      contains('through the letter picker'),
      reason: 'device 3 must have driven the picker, not been told the answer',
    );
    expect(
      deviceLog(3),
      contains('picked up'),
      reason: 'device 3 must have read a sheet another process wrote',
    );

    // The coordinator decides whether those words are a share of THIS wallet. It
    // compares the share image the device derived against its own expectation; a
    // mistyped word fails here.
    expect(
      await coord.checkPhysicalBackup(
        accessStructureRef: asRef!,
        phase: phase,
        encryptionKey: encryptionKey,
      ),
      isTrue,
      reason: 'the retyped backup is not a share of this wallet',
    );

    // M7e. Consolidation: the typed share REPLACES whatever the device held, and the
    // device is then a member of the access structure.
    await coord.tellDeviceToConsolidatePhysicalBackup(
      accessStructureRef: asRef!,
      phase: phase,
      encryptionKey: encryptionKey,
      deviceName: 'restored-3',
    );
    await until<bool>(
      'device 3 to hold a share of this wallet',
      () => coord.accessStructuresInvolvingDevice(deviceId: blank).isNotEmpty
          ? true
          : null,
    );
    // It holds device 0's share, which is the point: a human carried one sheet of paper
    // from one unit to another. Re-read, because `access` predates the consolidation.
    final after = coord.getAccessStructure(asRef: asRef!)!;
    expect(
      after.getDeviceShortShareIndex(deviceId: blank),
      after.getDeviceShortShareIndex(deviceId: source),
    );

    // The device, not the coordinator, named itself: `SetName` is what turns
    // `DeviceMode::Blank` into `Ready`, and only a `Ready` device is ever offered a
    // signing request by `SigningDispatcher::connected`.
    await until<bool>(
      'the restored device to report its committed name',
      () => coord.getConnectedDevice(id: blank)?.name == 'restored-3'
          ? true
          : null,
    );

    final nonceStates = <NonceReplenishState>[];
    final nonceSub = coord
        .replenishNonces(
          nonceRequest: coord.createNonceRequest(devices: [blank]),
          devices: [blank],
        )
        .listen(nonceStates.add);
    try {
      await until<bool>(
        'the restored device to hand over a nonce stream',
        () => (nonceStates.isNotEmpty && nonceStates.last.isFinished())
            ? true
            : null,
      );
    } finally {
      letGo(nonceSub);
    }
    expect(coord.noncesAvailable(id: blank), greaterThan(0));

    final foreign = await coldsnapTool('regtest.py', ['newaddress']);
    final build = wallet.buildTx(coord: coord, masterAppkey: masterAppkey!)!;
    build.setConfirmationTarget(
      target: const ConfirmationTarget.custom(feerate),
    );
    build.setRecipientWithUri(recipient: 0, uri: foreign);
    build.setAmount(recipient: 0, amount: sendSats ~/ 4);
    final plan = build.tryFinish();
    final inputCount = plan.inputCount();
    final unsigned = wallet.commitSend(coord: coord, plan: plan);

    final states = <SigningState>[];
    final sub = coord
        .startSigningTx(
          accessStructureRef: asRef!,
          unsignedTx: unsigned,
          devices: [idOf(1), blank],
        )
        .listen(states.add);
    try {
      final session = await until<SigningState>(
        'the signing session to open',
        () => states.isEmpty ? null : states.last,
      );
      await requestSharesFrom([idOf(1), blank], states, session.sessionId);

      // THE LOST REPLY: the restored device consented and signed, and the rig dropped
      // the frame. The coordinator must not have its share.
      await until<bool>(
        'the restored device to sign and lose its first reply',
        () => deviceLog(3).contains('SIGNATURE REPLY LOST ON THE WIRE')
            ? true
            : null,
      );
      await until<bool>(
        'device 1\'s share to arrive',
        () => states.last.gotShares.any((d) => d.toHex() == idOf(1).toHex())
            ? true
            : null,
      );
      expect(
        states.last.gotShares.any((d) => d.toHex() == blank.toHex()),
        isFalse,
        reason: 'a reply the rig dropped reached the coordinator',
      );
      expect(states.last.finishedSignatures, isNull);

      // REPLUG, the same way the replug test does it: the manifest line goes, then
      // comes back, and the dispatcher's own `connected()` re-offers the device.
      final manifest = File(manifestPath);
      final lines = manifest.readAsLinesSync();
      final port = File('$rigDir/identities.tsv')
          .readAsLinesSync()
          .firstWhere((l) => l.contains(blank.toHex()))
          .split('\t')
          .first;
      manifest.writeAsStringSync(
        lines.where((l) => l != port).join('\n') + '\n',
      );
      await until<bool>(
        'the restored device to disappear',
        () => coord.getConnectedDevice(id: blank) == null ? true : null,
      );
      final mark = states.length;
      manifest.writeAsStringSync(lines.join('\n') + '\n');
      await until<bool>(
        'the dispatcher to re-offer the replugged device a request',
        () =>
            states
                .skip(mark)
                .any(
                  (st) => st.connectedButNeedRequest.any(
                    (d) => d.toHex() == blank.toHex(),
                  ),
                )
            ? true
            : null,
      );
      // THE RE-SENT REQUEST: same session, same nonces. The core answers it from the
      // signing state it wrote to flash the first time; a fresh nonce would be
      // `IndexUsed` on the device or a share the coordinator cannot combine.
      coord.requestDeviceSign(
        deviceId: blank,
        sessionId: session.sessionId,
        encryptionKey: encryptionKey,
      );
      final done = await until<SigningState>(
        'a signature from the restored device and one other',
        () {
          final last = states.last;
          if (last.aborted != null) {
            throw StateError('signing ABORTED: ${last.aborted}');
          }
          return last.finishedSignatures != null ? last : null;
        },
      );
      expect(
        done.gotShares.map((d) => d.toHex()),
        containsAll([idOf(1).toHex(), blank.toHex()]),
      );
      expect(deviceLog(3), isNot(contains('IndexUsed')));
      // The replug was a POWER CYCLE of the stub after keygen: its session was rebuilt
      // from fake flash, so the share it signs with below was read back off flash.
      expect(deviceLog(3), contains('REPLUG RESTART'));
      expect(
        RegExp('SignatureRequest -> approved').allMatches(deviceLog(3)).length,
        2,
        reason: 'the restored device consents once per request it was sent',
      );

      final signed = await unsigned.withSignatures(
        signatures: done.finishedSignatures!,
      );
      // INDEPENDENT OF THE SIGNER: BIP-341 sighashes recomputed from the transaction's
      // own bytes and prevouts, checked with `secp256k1::verify_schnorr`.
      expect(
        wallet.verifyTaprootSignatures(tx: signed),
        inputCount,
        reason: 'the restored device\'s signature must verify on every input',
      );
      await coldsnapTool('regtest.py', ['accept', wallet.testTxHex(tx: signed)]);
    } finally {
      letGo(sub);
    }
  }, timeout: const Timeout(Duration(minutes: 6)));

  firstApp(
    'unplug and replug preserves the identity and the wallet',
    () async {
      final manifest = File(manifestPath);
      final lines = manifest.readAsLinesSync();
      final victim = idOf(0);
      final port = lines.firstWhere((l) => l.startsWith('/dev/'));

      // REMOVING A LINE IS AN UNPLUG: the test transport re-reads the manifest on every
      // `available_ports()` call, and `UsbSerialManager` turns a port that stopped being
      // there into a `DeviceChange::Disconnected`. No app restart is involved.
      manifest.writeAsStringSync(
        lines.where((l) => l != port).join('\n') + '\n',
      );
      await until<bool>(
        'device 0 to disappear from the app\'s device list',
        () => coord.getConnectedDevice(id: victim) == null ? true : null,
      );
      // The wallet is untouched by a device leaving.
      expect(coord.getAccessStructure(asRef: asRef!), isNotNull);

      manifest.writeAsStringSync(lines.join('\n') + '\n');
      final back = await until<ConnectedDevice>(
        'device 0 to come back with the SAME DeviceId',
        () => coord.getConnectedDevice(id: victim),
      );
      expect(back.id.toHex(), victim.toHex());
      // Its name survived, because the name is in the device's flash and in the
      // coordinator's DB, not in the port.
      expect(back.name, 'rig-device-0');
      expect(back.isCompatible(), isTrue);
      expect(
        coord.accessStructuresInvolvingDevice(deviceId: victim),
        isNotEmpty,
      );
    },
    timeout: const Timeout(Duration(minutes: 3)),
  );

  firstApp(
    'before the restart: record what the next app process must reload',
    () async {
      final access = coord.getAccessStructure(asRef: asRef!)!;
      final next = wallet.nextAddress(masterAppkey: masterAppkey!);
      final utxos = wallet.utxoCount(masterAppkey: masterAppkey!);
      // Non-trivial, or reloading it proves nothing: a revealed/used address frontier
      // past 0, a coin, and a name and a share on every rig device.
      expect(next.index, greaterThan(0), reason: 'no address was ever used');
      expect(utxos, greaterThan(0));
      final devices = <String, Object?>{};
      for (var i = 0; i < 4; i++) {
        final name = coord.getDeviceName(id: idOf(i));
        final share = access.getDeviceShortShareIndex(deviceId: idOf(i));
        expect(name, isNotNull, reason: 'rig device $i has no name to reload');
        expect(
          share,
          isNotNull,
          reason: 'rig device $i has no share to reload',
        );
        devices['$i'] = {'id': idOf(i).toHex(), 'name': name, 'share': share};
      }
      File(restartSnapshotPath).writeAsStringSync(
        jsonEncode({
          'pid': pid,
          'keyId': asRef!.keyId.toHex(),
          'accessStructureId': hex.encode(
            asRef!.accessStructureId.field0.toList(),
          ),
          'keyName': coord.getFrostKey(keyId: asRef!.keyId)!.keyName(),
          'threshold': access.threshold(),
          'devices': devices,
          'nextIndex': next.index,
          'nextAddress': next.address.toString(),
          'utxoCount': utxos,
        }),
      );
    },
  );

  secondApp(
    'after a real app restart: the wallet, its keys and device names are reloaded '
    'from disk, and the next address is the one the first process derived',
    () async {
      final snap =
          jsonDecode(File(restartSnapshotPath).readAsStringSync())
              as Map<String, dynamic>;
      // A NEW PROCESS, and the old one is gone -- not a widget rebuild or a reset.
      expect(
        pid,
        isNot(snap['pid']),
        reason: 'run 2 is the same process as run 1',
      );
      final probe = await Process.run('kill', ['-0', '${snap['pid']}']);
      expect(
        probe.exitCode,
        isNot(0),
        reason: 'the first app process ${snap['pid']} is still running',
      );

      // No keygen ran in this process: the one key is what the sqlite DB held.
      final keys = coord.keyState().keys;
      expect(
        keys.map((k) => k.keyId().toHex()).toList(),
        [snap['keyId']],
        reason:
            'the reloaded app does not hold exactly the first process\'s wallet',
      );
      final key = keys.single;
      expect(key.keyName(), snap['keyName']);
      final access = key.accessStructures().singleWhere(
        (a) =>
            hex.encode(
              a.accessStructureRef().accessStructureId.field0.toList(),
            ) ==
            snap['accessStructureId'],
      );
      asRef = access.accessStructureRef();
      masterAppkey = key.masterAppkey();
      expect(access.threshold(), snap['threshold']);

      final devices = (snap['devices'] as Map<String, dynamic>).map(
        (k, v) => MapEntry(int.parse(k), v as Map<String, dynamic>),
      );
      for (final MapEntry(key: i, value: d) in devices.entries) {
        final id = idOf(i);
        expect(id.toHex(), d['id'], reason: 'rig device $i changed identity');
        expect(
          coord.getDeviceName(id: id),
          d['name'],
          reason: 'the coordinator DB did not reload rig device $i\'s name',
        );
        expect(
          access.getDeviceShortShareIndex(deviceId: id),
          d['share'],
          reason: 'the reloaded access structure lost rig device $i\'s share',
        );
        await until<bool>(
          'rig device $i to reconnect to the new app under its name',
          () =>
              coord.getConnectedDevice(id: id)?.name == d['name'] ? true : null,
        );
      }

      // bdk: the address frontier and the coin came back off disk.
      final next = wallet.nextAddress(masterAppkey: masterAppkey!);
      expect(
        next.index,
        snap['nextIndex'],
        reason: 'address frontier not reloaded',
      );
      expect(next.address.toString(), snap['nextAddress']);
      expect(
        wallet.utxoCount(masterAppkey: masterAppkey!),
        snap['utxoCount'],
        reason: 'the bdk wallet did not reload its coins',
      );
    },
    timeout: const Timeout(Duration(minutes: 3)),
  );

  secondApp(
    'after the restart: the reloaded wallet builds a transaction and the devices sign it',
    () async {
      // NO funding here: the only coin is the one run 1's process was handed, reloaded
      // from bdk, and still unspent on the regtest node that outlived the restart.
      final foreign = await coldsnapTool('regtest.py', ['newaddress']);
      final build = wallet.buildTx(coord: coord, masterAppkey: masterAppkey!)!;
      build.setConfirmationTarget(
        target: const ConfirmationTarget.custom(feerate),
      );
      build.setRecipientWithUri(recipient: 0, uri: foreign);
      build.setAmount(recipient: 0, amount: sendSats ~/ 3);
      final plan = build.tryFinish();
      final inputCount = plan.inputCount();
      final unsigned = wallet.commitSend(coord: coord, plan: plan);

      final signers = [idOf(0), idOf(1)];
      for (final id in signers) {
        expect(
          coord.noncesAvailable(id: id),
          greaterThan(0),
          reason: 'the coordinator DB did not reload ${id.toHex()}\'s nonces',
        );
      }
      final before = {
        for (final i in [0, 1]) i: glassRows(i).length,
      };
      final states = <SigningState>[];
      final sub = coord
          .startSigningTx(
            accessStructureRef: asRef!,
            unsignedTx: unsigned,
            devices: signers,
          )
          .listen(states.add);
      try {
        final session = await until<SigningState>(
          'the signing session to open',
          () => states.isEmpty ? null : states.last,
        );
        await requestSharesFrom(signers, states, session.sessionId);
        final done = await until<SigningState>(
          '$threshold signature shares after the restart',
          () {
            final last = states.last;
            if (last.aborted != null) {
              throw StateError('signing ABORTED: ${last.aborted}');
            }
            return last.finishedSignatures != null ? last : null;
          },
        );
        for (final i in [0, 1]) {
          final flat = glassRows(
            i,
          ).skip(before[i]!).join().replaceAll(RegExp(r'\s'), '');
          expect(
            flat,
            contains(foreign),
            reason: 'device $i: no recipient on glass',
          );
          expect(
            flat,
            contains('${sendSats ~/ 3}'),
            reason: 'device $i: no amount',
          );
        }
        final signed = await unsigned.withSignatures(
          signatures: done.finishedSignatures!,
        );
        // Independent BIP-341 recomputation over the prevouts the RELOADED wallet holds.
        expect(wallet.verifyTaprootSignatures(tx: signed), inputCount);
        await coldsnapTool('regtest.py', [
          'accept',
          wallet.testTxHex(tx: signed),
        ]);
      } finally {
        letGo(sub);
      }
      final snap =
          jsonDecode(File(restartSnapshotPath).readAsStringSync())
              as Map<String, dynamic>;
      File(
        restartSnapshotPath,
      ).writeAsStringSync(jsonEncode({...snap, 'reloadedByPid': pid}));
    },
    timeout: const Timeout(Duration(minutes: 5)),
  );

  // TASK 08. LAST, because it destroys rig device 1's share and every test above needs
  // it. What it drives is the app's own erase path (`device.dart`'s erase dialog), minus
  // the widgets: the same `eraseDevice` stream, the same `deleteShare` on `Confirmed`,
  // and the same dismissal condition -- the OLD id leaving the device list. The widget
  // tree is not pumped here, so the dialog itself is not rendered; its inputs are.
  secondApp(
    'erase: a declined question writes nothing, an approved one confirms only after '
    'deletion, and the reset device comes back blank under a new id',
    () async {
      expect(
        requireEnv('COLDSNAP_RIG_ERASE').split(','),
        contains('1'),
        reason: 'run under tools/app-rig-test.sh, which passes --erase 1',
      );
      final victim = idOf(1);
      final victimHex = victim.toHex();
      expect(coord.getConnectedDevice(id: victim)!.capabilities().erase, isTrue);
      expect(coord.accessStructuresInvolvingDevice(deviceId: victim), isNotEmpty);

      // 1. DECLINED AT THE GLASS. The protocol has no refusal message, so the app's
      // dialog stays on `WaitingForConfirmation` until the human cancels it; the Cancel
      // button's own calls (`sendCancel`) end it here, plus the protocol cancel.
      final declined = <EraseDeviceState>[];
      final declineSub = coord
          .eraseDevice(deviceId: victim)
          .listen(declined.add);
      try {
        await until<bool>(
          'device 1 to decline its first erase question at its glass',
          () => deviceLog(1).contains('DECLINED DataErase') ? true : null,
        );
      } finally {
        await coord.sendCancel(id: victim);
        letGo(declineSub, cancelProtocol: true);
      }
      expect(declined, isNot(contains(EraseDeviceState.confirmed)));
      expect(deviceLog(1), isNot(contains('ERASED')));
      final kept = coord.getConnectedDevice(id: victim);
      expect(kept, isNotNull, reason: 'a declined erase must not reset the device');
      expect(kept!.name, 'rig-device-1');
      expect(coord.accessStructuresInvolvingDevice(deviceId: victim), isNotEmpty);

      // 2. APPROVED. `Confirmed` is the late ack: a cold-snap Mk4 sends
      // `EraseConfirmed` only after every sensitive page reads back blank, where
      // upstream sends it after the first sector.
      final states = <EraseDeviceState>[];
      final eraseSub = coord.eraseDevice(deviceId: victim).listen(states.add);
      try {
        await until<bool>(
          'EraseConfirmed from device 1 after its second, approved question',
          () => states.contains(EraseDeviceState.confirmed) ? true : null,
        );
      } finally {
        letGo(eraseSub);
      }
      // The stub logs the deletion BEFORE it writes the ack to the wire.
      expect(deviceLog(1), contains('ERASED on the randomised digit'));
      final reset = RegExp(
        r'RESET after erase and rebuilt from flash as (?:DeviceId\()?([0-9a-f]+)\)?: '
        r'0 shares, no name',
      ).firstMatch(deviceLog(1));
      expect(reset, isNotNull, reason: 'device 1 must have rebuilt itself blank');
      final freshHex = reset!.group(1)!;
      expect(freshHex, isNot(victimHex));

      // The dialog's own step on `Confirmed` (`device.dart`'s `dropErasedDeviceShares`,
      // the function the dialog calls): drop the device's share from every access
      // structure it was in.
      await dropErasedDeviceShares(coord, victim);
      expect(coord.accessStructuresInvolvingDevice(deviceId: victim), isEmpty);

      // 3. THE RESET'S USB DROP. The dialog ("Waiting for device reset") dismisses only
      // when the OLD id leaves the device list. A real unit's reset drops USB; the stub
      // cannot drop one pty for one of its sessions, so the old id is still listed
      // until the port goes -- which is the latency the dialog has to sit through.
      expect(
        coord.getConnectedDevice(id: victim),
        isNotNull,
        reason: 'the stub models no USB drop; only the unplug below removes the old id',
      );
      final manifest = File(manifestPath);
      final lines = manifest.readAsLinesSync();
      final port = File('$rigDir/identities.tsv')
          .readAsLinesSync()
          .firstWhere((l) => l.contains(victimHex))
          .split('\t')
          .first;
      manifest.writeAsStringSync(
        lines.where((l) => l != port).join('\n') + '\n',
      );
      await until<bool>(
        'the erased device\'s old id to leave the device list (dialog dismissal)',
        () => coord.getConnectedDevice(id: victim) == null ? true : null,
      );
      manifest.writeAsStringSync(lines.join('\n') + '\n');
      final fresh = await until<ConnectedDevice>(
        'the erased device to come back under its NEW id',
        () {
          for (final d in coord.deviceListState().devices) {
            if (d.id.toHex() == freshHex) return d;
          }
          return null;
        },
      );
      expect(fresh.name, isNull, reason: 'an erased device has no name');
      expect(fresh.isCompatible(), isTrue);
      expect(coord.accessStructuresInvolvingDevice(deviceId: fresh.id), isEmpty);
      expect(coord.getConnectedDevice(id: victim), isNull,
          reason: 'the old identity must never come back');
    },
    timeout: const Timeout(Duration(minutes: 3)),
  );

  // FIX 2a. An erase CUT BY A POWER LOSS, at every point the rig scripts
  // (`tools/app-rig-test.sh --erase-cut N:KEYS`, `stub.rs::erase_keys`):
  //   p  before the marker commits: the device reboots as ITSELF with its share, and
  //      the app keeps the share (fail closed) -- nothing is confirmed;
  //   c  after the commit and one share sector, no ack sent;
  //   a  after deletion with EraseConfirmed still in RAM, lost unwritten;
  //   f  in `finish`, after EraseConfirmed was written (confirmed at once; the boot's
  //      second ack is a duplicate nobody claims).
  // For c/a/f boot's `erase::recover` finishes the erase and acks from the ORIGINAL
  // id before announcing a fresh one; the app's `EraseDevice` (no disconnect
  // handler) confirms through the same arm as the test above, and the dialog's own
  // `dropErasedDeviceShares` drops the share. Host stub over ptys with fake flash: a
  // manifest unplug models the USB drop; no STM32 erase physics.
  secondApp(
    'erase cut by a power loss at every scripted point: a committed one is finished '
    'at boot and the app drops the share under the old id, an uncommitted one keeps it',
    () async {
      final specs = requireEnv('COLDSNAP_RIG_ERASE_CUT').split(',');
      expect(specs, isNotEmpty, reason: 'run under tools/app-rig-test.sh (--erase-cut)');
      final manifest = File(manifestPath);
      final lines = manifest.readAsLinesSync();
      int count(int rigIndex, String what) => what.allMatches(deviceLog(rigIndex)).length;

      Future<void> cycle(int rigIndex, DeviceId victim, String kind) async {
        final victimHex = victim.toHex();
        expect(coord.getConnectedDevice(id: victim)!.capabilities().erase, isTrue);
        expect(coord.accessStructuresInvolvingDevice(deviceId: victim), isNotEmpty);
        final cutMark = 'POWER CUT mid-erase [$kind]';
        final cuts = count(rigIndex, cutMark);
        final recoveries = count(rigIndex, 'erase::recover FINISHED the cut erase at boot');
        final keptBoots = count(rigIndex, 'rebooted after a pre-commit power cut');
        final states = <EraseDeviceState>[];
        final eraseSub = coord.eraseDevice(deviceId: victim).listen(states.add);
        var confirmed = 0;
        try {
          await until<bool>(
            'device $rigIndex to lose power mid-erase [$kind]',
            () => count(rigIndex, cutMark) > cuts ? true : null,
          );
          if (kind == 'f') {
            // The ack was written before the cut: confirmed now, before any reboot.
            await until<bool>(
              'EraseConfirmed written before the cut in finish',
              () => states.contains(EraseDeviceState.confirmed) ? true : null,
            );
          } else {
            // No ack left the device: nothing may be confirmed and nothing dropped.
            await Future<void>.delayed(const Duration(seconds: 1));
            expect(states, isNot(contains(EraseDeviceState.confirmed)),
                reason: '[$kind] confirmed with no ack on the wire');
            expect(coord.accessStructuresInvolvingDevice(deviceId: victim), isNotEmpty);
          }

          // The power cut drops USB: unplug, and the old id leaves the device list.
          final port = File('$rigDir/identities.tsv')
              .readAsLinesSync()
              .firstWhere((l) => l.contains(victimHex))
              .split('\t')
              .first;
          manifest.writeAsStringSync(
            lines.where((l) => l != port).join('\n') + '\n',
          );
          await until<bool>(
            'the powered-off device\'s old id to leave the device list [$kind]',
            () => coord.getConnectedDevice(id: victim) == null ? true : null,
          );
          if (kind != 'f') expect(states, isNot(contains(EraseDeviceState.confirmed)));

          // Power back: boot, reconnect.
          manifest.writeAsStringSync(lines.join('\n') + '\n');
          if (kind == 'p') {
            await until<bool>(
              'device $rigIndex to boot back as itself after a pre-commit cut',
              () => count(rigIndex, 'rebooted after a pre-commit power cut') > keptBoots &&
                      coord.getConnectedDevice(id: victim) != null
                  ? true
                  : null,
            );
            await Future<void>.delayed(const Duration(seconds: 1));
            expect(states, isNot(contains(EraseDeviceState.confirmed)),
                reason: 'a pre-commit cut confirmed an erase that never happened');
            expect(coord.accessStructuresInvolvingDevice(deviceId: victim), isNotEmpty,
                reason: 'fail closed: an uncommitted erase keeps the share');
            return;
          }
          await until<bool>(
            'boot recovery and EraseConfirmed from device $rigIndex\'s old id [$kind]',
            () => count(rigIndex, 'erase::recover FINISHED the cut erase at boot') >
                        recoveries &&
                    states.contains(EraseDeviceState.confirmed)
                ? true
                : null,
          );
          confirmed = states.where((s) => s == EraseDeviceState.confirmed).length;
        } finally {
          letGo(eraseSub, cancelProtocol: kind == 'p');
        }
        expect(confirmed, 1, reason: '[$kind] one confirmation, a duplicate ack claims nothing');
        await dropErasedDeviceShares(coord, victim);
        expect(coord.accessStructuresInvolvingDevice(deviceId: victim), isEmpty,
            reason: '[$kind] the app still holds the erased device\'s share');

        final recovered = RegExp(
          r'rebuilt from flash as (?:DeviceId\()?([0-9a-f]+)\)?: 0 shares, no name',
        ).allMatches(deviceLog(rigIndex)).last;
        final freshHex = recovered.group(1)!;
        expect(freshHex, isNot(victimHex));
        final fresh = await until<ConnectedDevice>(
          'the recovered device to come back under its NEW id [$kind]',
          () {
            for (final d in coord.deviceListState().devices) {
              if (d.id.toHex() == freshHex) return d;
            }
            return null;
          },
        );
        expect(fresh.name, isNull, reason: 'an erased device has no name');
        expect(coord.accessStructuresInvolvingDevice(deviceId: fresh.id), isEmpty);
        expect(coord.getConnectedDevice(id: victim), isNull,
            reason: 'the old identity must never come back');
      }

      final kinds = <String>[];
      for (final spec in specs) {
        final parts = spec.split(':');
        final rigIndex = int.parse(parts[0]);
        for (final kind in parts[1].split('')) {
          kinds.add(kind);
          // Every scripted key but the last is `p`, which keeps the same id.
          await cycle(rigIndex, idOf(rigIndex), kind);
        }
      }
      expect(kinds.toSet(), containsAll(<String>['p', 'c', 'a', 'f']),
          reason: 'every scripted cut point must be driven end to end');
    },
    timeout: const Timeout(Duration(minutes: 8)),
  );
}

/// The number of prompts this rig device has refused, off its own log. The protocol has
/// no decline message, so this is the only place a refusal is stated.
int _countDeclines(int rigIndex) =>
    RegExp(r'DECLINED').allMatches(deviceLog(rigIndex)).length;

/// A satoshi value as it appears in a serialized transaction output: little-endian u64,
/// hex. Used to tamper with a signed transaction so both signature checkers have to
/// reject it.
String _le64(int value) {
  final bytes = Uint8List(8);
  var v = value;
  for (var i = 0; i < 8; i++) {
    bytes[i] = v & 0xff;
    v >>= 8;
  }
  return hex.encode(bytes);
}

/// Minimal hex, so this file needs no extra dependency.
const hex = _Hex();

class _Hex extends Converter<List<int>, String> {
  const _Hex();
  @override
  String convert(List<int> input) =>
      input.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  String encode(List<int> input) => convert(input);
}
