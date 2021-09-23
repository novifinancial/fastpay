use super::*;

impl Coin {
    pub fn new(
        parameters: &mut Parameters,
        secret: &SecretKey,
        value: &Scalar,
        id: &Scalar,
    ) -> Self {
        let h0 = parameters.hs[0];
        let h1 = parameters.hs[1];
        let o = parameters.random_scalar();
        let cm = h0 * value + h1 * id + parameters.g1 * o;

        let h = Parameters::hash_to_g1(cm.to_bytes());

        let y0 = &secret.ys[0];
        let y1 = &secret.ys[1];
        Self(h, h * value * y0 + h * id * y1 + h * secret.x)
    }
}
