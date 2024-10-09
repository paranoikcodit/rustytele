use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;

pub fn ige256(in_data: &[u8], key: &[u8], iv: &[u8], encrypt: bool) -> Vec<u8> {
    const AES_BLOCK_SIZE: usize = 16;

    assert_eq!(key.len(), 32, "Key must be 32 bytes long.");
    assert_eq!(iv.len(), 32, "IV must be 32 bytes long.");
    assert_eq!(
        in_data.len() % AES_BLOCK_SIZE,
        0,
        "Input data length must be a multiple of 16 bytes."
    );

    let mut out_data = vec![0u8; in_data.len()];
    let mut iv1 = [0u8; AES_BLOCK_SIZE];
    let mut iv2 = [0u8; AES_BLOCK_SIZE];
    let mut chunk = [0u8; AES_BLOCK_SIZE];
    let mut buffer = [0u8; AES_BLOCK_SIZE];

    // Initialize iv1 and iv2
    if encrypt {
        iv1.copy_from_slice(&iv[0..AES_BLOCK_SIZE]);
        iv2.copy_from_slice(&iv[AES_BLOCK_SIZE..AES_BLOCK_SIZE * 2]);
    } else {
        iv2.copy_from_slice(&iv[0..AES_BLOCK_SIZE]);
        iv1.copy_from_slice(&iv[AES_BLOCK_SIZE..AES_BLOCK_SIZE * 2]);
    }

    let cipher = Aes256::new(GenericArray::from_slice(key));

    for i in (0..in_data.len()).step_by(AES_BLOCK_SIZE) {
        // Copy chunk
        chunk.copy_from_slice(&in_data[i..i + AES_BLOCK_SIZE]);

        // Compute buffer = in_data[i..i+AES_BLOCK_SIZE] ^ iv1
        for j in 0..AES_BLOCK_SIZE {
            buffer[j] = in_data[i + j] ^ iv1[j];
        }

        // Encrypt or decrypt buffer
        let mut block = GenericArray::clone_from_slice(&buffer);

        if encrypt {
            cipher.encrypt_block(&mut block);
        } else {
            cipher.decrypt_block(&mut block);
        }

        // XOR with iv2 and write to out_data
        for j in 0..AES_BLOCK_SIZE {
            out_data[i + j] = block[j] ^ iv2[j];
        }

        // Update iv1 and iv2
        iv1.copy_from_slice(&out_data[i..i + AES_BLOCK_SIZE]);
        iv2.copy_from_slice(&chunk);
    }

    out_data
}
