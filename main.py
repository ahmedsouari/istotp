import can

class IsoTP:
    # ISO-TP frame types
    SINGLE_FRAME = 0x0
    FIRST_FRAME = 0x1
    CONSECUTIVE_FRAME = 0x2
    FLOW_CONTROL = 0x3
    
    def __init__(self, can_channel='can0', bitrate=500000, tx_id=0x7E0, rx_id=0x7E8):
        self.sequence_number = 0
        self.tx_id = tx_id
        self.rx_id = rx_id
        
        # Initialize CAN bus
        self.bus = can.interface.Bus(channel=can_channel, 
                                   bustype='socketcan',
                                   bitrate=bitrate)
        
    def send_bytes(self, data):
        """
        Send bytes according to ISO-TP protocol
        data: bytes array to send
        """
        if len(data) <= 7:
            # Single frame
            frame = bytearray([len(data) & 0xF])  # PCI byte
            frame.extend(data)
            return self._send_frame(frame)
        else:
            # Multi frame
            # First frame
            length = len(data)
            frame = bytearray([(self.FIRST_FRAME << 4) | ((length >> 8) & 0xF), length & 0xFF])
            frame.extend(data[:6])
            self._send_frame(frame)
            
            # Consecutive frames
            offset = 6
            self.sequence_number = 1
            
            while offset < len(data):
                remaining = data[offset:offset + 7]
                frame = bytearray([(self.CONSECUTIVE_FRAME << 4) | (self.sequence_number & 0xF)])
                frame.extend(remaining)
                self._send_frame(frame)
                
                offset += 7
                self.sequence_number = (self.sequence_number + 1) & 0xF
                
    def _send_frame(self, frame):
        """
        Send a single ISO-TP frame through CAN with extended ID
        """
        msg = can.Message(
            arbitration_id=self.tx_id,
            data=frame,
            is_extended_id=True  # Changed to True for extended CAN
        )
        try:
            self.bus.send(msg)
            return True
        except can.CanError:
            print("Error sending CAN frame")
            return False

# Example usage
if __name__ == "__main__":
    # Using extended CAN ID (29 bits)
    isotp = IsoTP(can_channel='can0', tx_id=0x18DA0FFE, rx_id=0x18DAF100)
    test_data = bytes([0x32,0x11,0xAA,0x33,0x44,0x88,0x44,0x88])
    isotp.send_bytes(test_data)
