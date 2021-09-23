use crate::setup::Parameters;
use bls12_381::Scalar;
use core::iter::Sum;
use core::ops::Mul;
use ff::Field as _;

/// Represents a polynomial.
pub struct Polynomial {
    coefficients: Vec<Scalar>,
}

impl Polynomial {
    /// Create a random polynomial with a specific degree.
    pub fn random(parameters: &mut Parameters, degree: usize) -> Self {
        Polynomial {
            coefficients: parameters.n_random_scalars(degree + 1),
        }
    }

    /// Evaluate the polynomial at point x.
    pub fn evaluate(&self, x: &Scalar) -> Scalar {
        if self.coefficients.is_empty() {
            Scalar::zero()
        } else if x.is_zero().into() {
            *self.coefficients.first().unwrap()
        } else {
            self.coefficients
                .iter()
                .enumerate()
                .map(|(i, coefficient)| coefficient * x.pow(&[i as u64, 0, 0, 0]))
                .sum()
        }
    }

    /// Computes the Lagrange interpolation at the origin.
    pub fn lagrange_interpolate<T>(points: &[(T, u64)]) -> T
    where
        T: Sum,
        for<'a> &'a T: Mul<&'a Scalar, Output = T>,
    {
        let (values, indices): (Vec<_>, Vec<_>) =
            points.iter().map(|(v, i)| (v, Scalar::from(*i))).unzip();
        let coefficients = Self::lagrange_coefficients(&indices);
        values
            .into_iter()
            .zip(coefficients.iter())
            .map(|(value, coefficient)| value * coefficient)
            .sum()
    }

    /// Helper function computing the Lagrange coefficients.
    fn lagrange_coefficients(indices: &[Scalar]) -> Vec<Scalar> {
        let x = Scalar::zero();
        indices
            .iter()
            .map(|j| {
                let (num, den) = indices
                    .iter()
                    .filter(|k| k != &j)
                    .fold((Scalar::one(), Scalar::one()), |(num, den), k| {
                        (num * (x - k), den * (j - k))
                    });
                num * den.invert().unwrap()
            })
            .collect()
    }
}
