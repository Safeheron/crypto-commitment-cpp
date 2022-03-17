//
// Created by 何剑虹 on 2021/7/5.
//

#ifndef CPP_MPC_COMMITMENT_H
#define CPP_MPC_COMMITMENT_H

#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "kgd_number.h"
#include "kgd_curve_point.h"

namespace safeheron{
namespace commitment {

safeheron::bignum::BN CreateComWithBlind(safeheron::bignum::BN &num, safeheron::bignum::BN &blind_factor);

safeheron::bignum::BN CreateComWithBlind(curve::CurvePoint &point, safeheron::bignum::BN &blind_factor);

safeheron::bignum::BN CreateComWithBlind(std::vector<curve::CurvePoint> &points, safeheron::bignum::BN &blind_factor);

}
}


#endif //CPP_MPC_COMMITMENT_H
