#[repr(C)]
#[derive(Copy, Clone)]
pub struct TxMetadataCompletion {
    pub timestamp: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TxMetadataRequest {
    pub csum_start: u16,
    pub csum_offset: u16,
}

#[repr(C)]
pub union TxMetadataRc {
    pub request: TxMetadataRequest,
    pub completion: TxMetadataCompletion,
}

#[repr(C)]
pub struct TxMetadata {
    pub flags: u64,
    pub rc: TxMetadataRc,
}

impl TxMetadata {
    #[inline]
    pub const fn completion(flags: u64, timestamp: u64) -> Self {
        Self {
            flags,
            rc: TxMetadataRc {
                completion: TxMetadataCompletion { timestamp },
            },
        }
    }

    #[inline]
    pub const fn request(
        flags: u64,
        csum_start: u16,
        csum_offset: u16,
    ) -> Self {
        Self {
            flags,
            rc: TxMetadataRc {
                request: TxMetadataRequest {
                    csum_start,
                    csum_offset,
                },
            },
        }
    }
}
