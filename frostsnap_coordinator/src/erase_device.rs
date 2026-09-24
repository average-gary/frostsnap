use frostsnap_comms::{CommsMisc, CoordinatorSendBody, CoordinatorSendMessage};
use frostsnap_core::DeviceId;
use std::borrow::BorrowMut;

use crate::{Completion, Sink, UiProtocol};

#[derive(Clone, Debug, PartialEq)]
pub enum EraseDeviceState {
    /// Waiting for user to confirm erase on device
    WaitingForConfirmation,
    /// Device confirmed erase has started (first sector erased)
    Confirmed,
}

pub struct EraseDevice {
    target_device: DeviceId,
    sent_request: bool,
    confirmed: bool,
    aborted: bool,
    sink: Box<dyn Sink<EraseDeviceState>>,
}

impl EraseDevice {
    pub fn new(target_device: DeviceId, sink: impl Sink<EraseDeviceState> + 'static) -> Self {
        Self {
            target_device,
            sent_request: false,
            confirmed: false,
            aborted: false,
            sink: Box::new(sink),
        }
    }
}

impl UiProtocol for EraseDevice {
    fn cancel(&mut self) {
        self.aborted = true;
    }

    fn is_complete(&self) -> Option<Completion> {
        if self.aborted {
            Some(Completion::Abort {
                send_cancel_to_all_devices: false,
            })
        } else if self.confirmed {
            Some(Completion::Success)
        } else {
            None
        }
    }

    fn poll(&mut self) -> Vec<CoordinatorSendMessage> {
        if !self.sent_request {
            self.sent_request = true;
            self.sink.send(EraseDeviceState::WaitingForConfirmation);
            vec![CoordinatorSendMessage::to(
                self.target_device,
                CoordinatorSendBody::DataErase,
            )]
        } else {
            vec![]
        }
    }

    /// Claims `EraseConfirmed` only from the target and only once `DataErase` went
    /// out. There is deliberately no `disconnected`: a cold-snap Mk4 whose erase was
    /// cut by power loss finishes it at boot and sends this ack from its ORIGINAL id
    /// after reconnecting under a fresh one, and this protocol must still be waiting.
    /// A duplicate ack after the first is not claimed and never reaches the sink.
    fn process_comms_message(&mut self, from: DeviceId, message: CommsMisc) -> bool {
        if self.sent_request
            && !self.confirmed
            && from == self.target_device
            && matches!(message, CommsMisc::EraseConfirmed)
        {
            self.confirmed = true;
            self.sink.send(EraseDeviceState::Confirmed);
            true
        } else {
            false
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn std::any::Any {
        self.borrow_mut()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::DeviceMode;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Seen(Arc<Mutex<Vec<EraseDeviceState>>>);
    impl Sink<EraseDeviceState> for Seen {
        fn send(&self, state: EraseDeviceState) {
            self.0.lock().unwrap().push(state);
        }
    }

    /// Fix 2a: the ack a cold-snap Mk4 sends after `erase::recover` finished an erase
    /// that a power cut interrupted. The target drops off USB, a NEW id connects on
    /// the same port, and `EraseConfirmed` arrives from the ORIGINAL id: the waiting
    /// protocol confirms through the same arm as an uninterrupted erase. Nothing else
    /// confirms it: not a stray ack from another device (or the fresh id), and not an
    /// ack that arrives before `DataErase` was sent.
    #[test]
    fn a_recovered_erase_ack_confirms_and_nothing_else_does() {
        let target = DeviceId([2; 33]);
        let fresh = DeviceId([3; 33]);
        let seen = Seen::default();
        let mut erase = EraseDevice::new(target, seen.clone());
        assert!(!erase.process_comms_message(target, CommsMisc::EraseConfirmed));
        assert!(erase.is_complete().is_none(), "acked before it was asked");
        assert_eq!(erase.poll().len(), 1, "DataErase to the target");
        erase.disconnected(target);
        erase.connected(fresh, DeviceMode::Blank);
        assert!(!erase.process_comms_message(fresh, CommsMisc::EraseConfirmed));
        assert!(!erase.process_comms_message(target, CommsMisc::BackupRecorded));
        assert!(erase.is_complete().is_none(), "a stray message confirmed the erase");
        assert!(erase.process_comms_message(target, CommsMisc::EraseConfirmed));
        assert!(matches!(erase.is_complete(), Some(Completion::Success)));
        assert!(
            !erase.process_comms_message(target, CommsMisc::EraseConfirmed),
            "a duplicate ack before clean_finished confirmed twice"
        );
        assert_eq!(
            *seen.0.lock().unwrap(),
            [EraseDeviceState::WaitingForConfirmation, EraseDeviceState::Confirmed]
        );
    }
}
