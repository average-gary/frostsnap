import 'package:flutter_test/flutter_test.dart';
import 'package:frostsnap/wallet_create.dart';

// The keygen party ceiling the wallet-create step gates on. It is a DECLARED
// capability of the firmware taking part (`DeviceCapabilities.maxKeygenDevices`),
// never a number the app picked: an all-native group declares none and is not
// capped, and a mixed group is held to the smallest ceiling present.
//
// This covers the pure predicate only. The REFUSAL is in Rust
// (`generate_new_key` consults `api::device_list::keygen_ceiling` before
// `BeginKeygen::new`), so a direct bridge call cannot get past it either; the
// Dart gate only stops the user reaching that error.

void main() {
  group('declaredKeygenCeiling', () {
    test('an all-native group declares no ceiling', () {
      expect(declaredKeygenCeiling([null, null, null]), isNull);
      expect(declaredKeygenCeiling([]), isNull);
    });

    test('the smallest declared ceiling wins in a mixed group', () {
      // ESP32 declares none, a cold-snap Mk4 declares 12.
      expect(declaredKeygenCeiling([null, 12, null]), 12);
      expect(declaredKeygenCeiling([12, 4, null, 12]), 4);
    });

    test('12 is the bound: 12 devices are inside it, 13 are over', () {
      final ceiling = declaredKeygenCeiling([null, 12])!;
      expect(12 <= ceiling, isTrue);
      expect(13 > ceiling, isTrue);
    });
  });
}
