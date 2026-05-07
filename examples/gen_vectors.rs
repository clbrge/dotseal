use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use dotseal::{seal_value_with_nonce, KEY_LEN, NONCE_LEN};

fn main() {
    let key: Vec<u8> = (0..KEY_LEN as u8).collect();
    let nonce: Vec<u8> = (32..32 + NONCE_LEN as u8).collect();
    let sealed =
        seal_value_with_nonce("secret-value", &key, "production", "API_SUPER_KEY", &nonce).unwrap();
    let payload_b64 = sealed.rsplit_once(':').unwrap().1;
    let payload: Vec<u8> = URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
    eprintln!("# base: {sealed}");
    eprintln!("# payload_len: {}", payload.len());

    let mut p = payload.clone();
    p[0] ^= 0x01;
    println!("nonce_bit_flip       enc:v1:{}", URL_SAFE_NO_PAD.encode(&p));

    let mut p = payload.clone();
    p[NONCE_LEN] ^= 0x01;
    println!("ciphertext_bit_flip  enc:v1:{}", URL_SAFE_NO_PAD.encode(&p));

    let mut p = payload.clone();
    let last = p.len() - 1;
    p[last] ^= 0x01;
    println!("tag_bit_flip         enc:v1:{}", URL_SAFE_NO_PAD.encode(&p));

    let p = payload[..NONCE_LEN].to_vec();
    println!("exactly_nonce_len    enc:v1:{}", URL_SAFE_NO_PAD.encode(&p));

    // padded variant of base sealed (URL_SAFE produces padding)
    println!("padded_payload       enc:v1:{}", URL_SAFE.encode(&payload));
}
