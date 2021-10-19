use super::*;

impl Polynomial {
    pub fn ones(degree: usize) -> Self {
        Polynomial {
            coefficients: (0..degree + 1).map(|_| Scalar::one()).collect(),
        }
    }
}

#[test]
fn evaluate() {
    let polynomial = Polynomial::ones(2);
    let origin = polynomial.evaluate(&Scalar::one());
    assert_eq!(origin, Scalar::from(3));
}

#[test]
fn interpolate() {
    let polynomial = Polynomial::ones(2);
    let origin = polynomial.evaluate(&Scalar::zero());
    assert_eq!(origin, Scalar::one());

    // Make (degree + 1) shares.
    let share_1 = polynomial.evaluate(&Scalar::from(2));
    let share_2 = polynomial.evaluate(&Scalar::from(4));
    let share_3 = polynomial.evaluate(&Scalar::from(6));

    // Reconstruct the origin.
    let points = vec![(share_1, 2), (share_2, 4), (share_3, 6)];
    let output = Polynomial::lagrange_interpolate(&points);
    assert_eq!(origin, output);
}

#[test]
fn interpolate_fail() {
    let polynomial = Polynomial::ones(2);
    let origin = polynomial.evaluate(&Scalar::zero());
    assert_eq!(origin, Scalar::one());

    // Make a few shares (but not enough).
    let share_1 = polynomial.evaluate(&Scalar::from(2));
    let share_2 = polynomial.evaluate(&Scalar::from(4));

    // Try to re-construct the origin.
    let points = vec![(share_1, 2), (share_2, 4)];
    let output = Polynomial::lagrange_interpolate(&points);
    assert!(origin != output);
}
