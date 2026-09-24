import 'package:flutter_test/flutter_test.dart';
import 'package:frostsnap/mk4_upgrade.dart';
import 'package:frostsnap/src/rust/api/firmware.dart';
import 'package:frostsnap/src/rust/lib.dart';

// A staging-only result must never read as installed. `Staged` is the peer's
// digest verdict over its PSRAM read-back; only `VerifiedReconnect` (which
// nothing in this app produces) is an installation.
void main() {
  final digest = Sha256Digest(field0: U8Array32.init());

  test('staged says NOT installed', () {
    final text = mk4UpgradeStateText(
      Mk4UpgradeState.staged(size: 397312, digest: digest),
    );
    expect(text, contains('NOT installed'));
    expect(text, isNot(startsWith('Installed')));
  });

  test('only a verified reconnect says installed', () {
    final states = [
      Mk4UpgradeState.transferring(chunksAcked: 3, totalChunks: 97),
      Mk4UpgradeState.staged(size: 397312, digest: digest),
      Mk4UpgradeState.installRequested(digest: digest),
    ];
    for (final s in states) {
      expect(mk4UpgradeStateText(s).startsWith('Installed'), isFalse);
    }
  });
}
