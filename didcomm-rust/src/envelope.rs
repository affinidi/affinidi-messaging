use crate::{jwe::envelope::JWE, jws::Jws, Message};

/// High level wrapper so we can serialize and deserialize the envelope types

enum Envelope {
    JWE(JWE),
    JWS(Jws),
    Message(Message),
}
