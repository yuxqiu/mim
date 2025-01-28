use std::marker::PhantomData;

use ark_ec::{
    hashing::curve_maps::wb::WBConfig, short_weierstrass::Projective, CurveConfig, CurveGroup,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::{FieldOpsBounds, FieldVar},
    groups::curves::short_weierstrass::AffineVar,
};
use ark_relations::r1cs::SynthesisError;

type Domain<P: WBConfig> = P::IsogenousCurve;
type CoDomain<P: WBConfig> = P;
type DomainBaseField<P: WBConfig> = <Domain<P> as CurveConfig>::BaseField;
type CoDomainBaseField<P: WBConfig> = <CoDomain<P> as CurveConfig>::BaseField;

/// Trait for mapping a point in Domain -> CoDomain
pub struct IsogenyMapGadget<
    P: WBConfig,
    FpDomain: FieldVar<DomainBaseField<P>, CF>,
    FpCoDomain: FieldVar<CoDomainBaseField<P>, CF>,
    CF: PrimeField,
> where
    for<'a> &'a FpDomain: FieldOpsBounds<'a, DomainBaseField<P>, FpDomain>,
    for<'a> &'a FpCoDomain: FieldOpsBounds<'a, CoDomainBaseField<P>, FpCoDomain>,
{
    _params: PhantomData<(P, FpDomain, FpCoDomain, CF)>,
}

impl<
        P: WBConfig,
        FpDomain: FieldVar<DomainBaseField<P>, CF>,
        FpCoDomain: FieldVar<CoDomainBaseField<P>, CF>,
        CF: PrimeField,
    > IsogenyMapGadget<P, FpDomain, FpCoDomain, CF>
where
    for<'a> &'a FpDomain: FieldOpsBounds<'a, DomainBaseField<P>, FpDomain>,
    for<'a> &'a FpCoDomain: FieldOpsBounds<'a, CoDomainBaseField<P>, FpCoDomain>,
{
    fn apply(
        &self,
        domain_point: AffineVar<<Projective<Domain<P>> as CurveGroup>::Config, FpDomain, CF>,
    ) -> Result<
        AffineVar<<Projective<CoDomain<P>> as CurveGroup>::Config, FpCoDomain, CF>,
        SynthesisError,
    > {
        todo!()
    }
}
