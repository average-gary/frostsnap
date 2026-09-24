import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:frostsnap/src/rust/api/firmware.dart';

import 'global.dart';

/// What the user is told for each state. `staged` is the peer's digest verdict
/// over its read-back and nothing more; only `verifiedReconnect` says installed.
String mk4UpgradeStateText(Mk4UpgradeState state) => switch (state) {
  Mk4UpgradeState_Transferring(:final chunksAcked, :final totalChunks) =>
    'Sent $chunksAcked of $totalChunks chunks',
  Mk4UpgradeState_Staged(:final size) =>
    'Staged $size bytes on the device. NOT installed: '
        'installing is a separate step this app does not perform.',
  Mk4UpgradeState_InstallRequested() =>
    'Install requested. Waiting for the device to reconnect.',
  Mk4UpgradeState_VerifiedReconnect() =>
    'Installed: the device reconnected running the staged image.',
};

/// Pick a Mk4 image, pick ONE port, stage. Every image check runs in Rust
/// (`start_mk4_upgrade`) before anything is sent.
Future<void> showMk4UpgradeDialog(BuildContext context) async {
  final picked = await FilePicker.platform.pickFiles(
    dialogTitle: 'Mk4 firmware image (firmware-signed.bin or .dfu)',
  );
  final path = picked?.files.single.path;
  if (path == null || !context.mounted) return;
  await showDialog(
    context: context,
    builder: (context) => _Mk4UpgradeDialog(imagePath: path),
  );
}

class _Mk4UpgradeDialog extends StatefulWidget {
  final String imagePath;
  const _Mk4UpgradeDialog({required this.imagePath});

  @override
  State<_Mk4UpgradeDialog> createState() => _Mk4UpgradeDialogState();
}

class _Mk4UpgradeDialogState extends State<_Mk4UpgradeDialog> {
  List<String> ports = coord.mk4UpgradePorts();
  String? status;
  bool running = false;

  void _start(String port) {
    setState(() {
      running = true;
      status = 'Starting on $port';
    });
    coord
        .startMk4Upgrade(port: port, imagePath: widget.imagePath)
        .listen(
          (state) => setState(() => status = mk4UpgradeStateText(state)),
          onError: (e) => setState(() {
            status = 'Failed: $e';
            running = false;
          }),
          onDone: () => setState(() => running = false),
        );
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Text('Stage firmware image'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Power the Mk4 up holding OK so only its upgrade listener is on '
            'the port, then choose that port. Nothing is sent to any other port.',
          ),
          SizedBox(height: 12),
          if (status == null)
            ...ports.map(
              (port) => ListTile(title: Text(port), onTap: () => _start(port)),
            ),
          if (status == null && ports.isEmpty)
            Text('No upgrade listener found yet.'),
          if (status != null) Text(status!),
        ],
      ),
      actions: [
        if (status == null)
          TextButton(
            onPressed: () => setState(() => ports = coord.mk4UpgradePorts()),
            child: Text('Refresh'),
          ),
        TextButton(
          onPressed: running ? null : () => Navigator.pop(context),
          child: Text('Close'),
        ),
      ],
    );
  }
}
