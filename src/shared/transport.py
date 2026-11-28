import asyncio

class TransportSession:
    def __init__(self) -> None:
        self.reader: asyncio.StreamReader
        self.writer: asyncio.StreamWriter

        self.sending_aes_key: bytes
        self.receiving_aes_key: bytes

        self.sending_hmac_key: bytes
        self.receiving_hmac_key: bytes

        self.sending_counter: bytes
        self.receiving_counter: bytes
