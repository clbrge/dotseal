use dotseal::{
    decrypt_value, parse_env, parse_env_value, seal_value_with_nonce, KEY_LEN, NONCE_LEN,
};
use proptest::prelude::*;

fn arb_key() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), KEY_LEN..=KEY_LEN)
}

fn arb_nonce() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), NONCE_LEN..=NONCE_LEN)
}

fn arb_env_name() -> impl Strategy<Value = String> {
    "[A-Za-z_][A-Za-z0-9_]{0,31}".prop_map(String::from)
}

fn arb_scope() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_.-]{1,16}".prop_map(String::from)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    #[test]
    fn seal_decrypt_roundtrips_for_arbitrary_inputs(
        key in arb_key(),
        nonce in arb_nonce(),
        scope in arb_scope(),
        name in arb_env_name(),
        plaintext in ".{0,256}",
    ) {
        let sealed = seal_value_with_nonce(&plaintext, &key, &scope, &name, &nonce).unwrap();
        let recovered = decrypt_value(&sealed, &key, &scope, &name).unwrap();
        prop_assert_eq!(&**recovered, &plaintext);
    }

    #[test]
    fn decrypt_rejects_swapped_scope_or_name(
        key in arb_key(),
        nonce in arb_nonce(),
        scope_a in arb_scope(),
        scope_b in arb_scope(),
        name_a in arb_env_name(),
        name_b in arb_env_name(),
        plaintext in ".{0,128}",
    ) {
        prop_assume!(scope_a != scope_b || name_a != name_b);
        let sealed = seal_value_with_nonce(&plaintext, &key, &scope_a, &name_a, &nonce).unwrap();
        if scope_a != scope_b {
            prop_assert!(decrypt_value(&sealed, &key, &scope_b, &name_a).is_err());
        }
        if name_a != name_b {
            prop_assert!(decrypt_value(&sealed, &key, &scope_a, &name_b).is_err());
        }
    }

    #[test]
    fn parse_env_value_never_panics(raw in ".{0,256}") {
        let _ = parse_env_value(&raw);
    }

    #[test]
    fn parse_env_never_panics(content in ".{0,512}") {
        let _ = parse_env(&content);
    }
}
