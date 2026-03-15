#[test]
fn transfer_queue_rejects_zero_length() {
    let mut queue = crate::drivers::gpu_support::engines::transfer::TransferQueue::new();
    let packet = crate::drivers::gpu_support::TransferPacket {
        src_bo: 1,
        dst_bo: 2,
        bytes: 0,
    };
    assert!(queue.submit(&packet).is_err());
}

