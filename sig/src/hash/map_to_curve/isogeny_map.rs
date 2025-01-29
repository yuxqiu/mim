use std::marker::PhantomData;

use ark_ec::{
    hashing::curve_maps::wb::WBConfig,
    short_weierstrass::{Affine, Projective},
    CurveConfig, CurveGroup,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::{FieldOpsBounds, FieldVar},
    groups::curves::short_weierstrass::AffineVar,
    poly::polynomial::univariate::dense::DensePolynomialVar,
    prelude::Boolean,
};
use ark_relations::r1cs::SynthesisError;

type Domain<P> = <P as WBConfig>::IsogenousCurve;
type CoDomain<P> = P;
type DomainBaseField<P> = <Domain<P> as CurveConfig>::BaseField;

/// Trait for mapping a point in Domain -> CoDomain
pub struct IsogenyMapGadget<
    P: WBConfig,
    FpDomainCoDomain: FieldVar<DomainBaseField<P>, CF>, // enforcing the same base field and variable for domain and codomain
    CF: PrimeField,
> where
    for<'a> &'a FpDomainCoDomain: FieldOpsBounds<'a, DomainBaseField<P>, FpDomainCoDomain>,
{
    _params: PhantomData<(P, FpDomainCoDomain, CF)>,
}

impl<P: WBConfig, FpDomainCoDomain: FieldVar<DomainBaseField<P>, CF>, CF: PrimeField>
    IsogenyMapGadget<P, FpDomainCoDomain, CF>
where
    for<'a> &'a FpDomainCoDomain: FieldOpsBounds<'a, DomainBaseField<P>, FpDomainCoDomain>,
{
    pub fn apply(
        domain_point: AffineVar<
            <Projective<Domain<P>> as CurveGroup>::Config,
            FpDomainCoDomain,
            CF,
        >,
    ) -> Result<
        AffineVar<<Projective<CoDomain<P>> as CurveGroup>::Config, FpDomainCoDomain, CF>,
        SynthesisError,
    > {
        let map = P::ISOGENY_MAP;
        let x_num = DensePolynomialVar::from_coefficients_slice(
            &map.x_map_numerator
                .iter()
                .map(|v| FpDomainCoDomain::constant(*v))
                .collect::<Vec<_>>(),
        );
        let x_den = DensePolynomialVar::from_coefficients_slice(
            &map.x_map_denominator
                .iter()
                .map(|v| FpDomainCoDomain::constant(*v))
                .collect::<Vec<_>>(),
        );

        let y_num = DensePolynomialVar::from_coefficients_slice(
            &map.y_map_numerator
                .iter()
                .map(|v| FpDomainCoDomain::constant(*v))
                .collect::<Vec<_>>(),
        );
        let y_den = DensePolynomialVar::from_coefficients_slice(
            &map.y_map_denominator
                .iter()
                .map(|v| FpDomainCoDomain::constant(*v))
                .collect::<Vec<_>>(),
        );

        // batch_inversion(&mut v);
        let v: [FpDomainCoDomain; 2] = [
            x_den.evaluate(&domain_point.x)?.inverse()?,
            y_den.evaluate(&domain_point.x)?.inverse()?,
        ];
        let img_x = x_num.evaluate(&domain_point.x)? * &v[0];
        let img_y = (y_num.evaluate(&domain_point.x)? * domain_point.y) * &v[1];

        // Affine::<Codomain>::new_unchecked(img_x, img_y)
        let first = AffineVar::<CoDomain<P>, FpDomainCoDomain, CF>::new(
            img_x,
            img_y,
            Boolean::constant(false),
        );

        let id: Affine<CoDomain<P>> = Affine::identity();

        // lazy way to select first / id
        // domain_point.infinity.select(&first, &id)
        let x = domain_point
            .infinity
            .select(&FpDomainCoDomain::constant(id.x), &first.x)?;
        let y = domain_point
            .infinity
            .select(&FpDomainCoDomain::constant(id.y), &first.y)?;

        Ok(AffineVar::new(x, y, domain_point.infinity))
    }
}
