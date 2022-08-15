#ifndef CPP_MPC_COMMITMENT_H
#define CPP_MPC_COMMITMENT_H

#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "kgd_number.h"
#include "kgd_curve_point.h"

namespace safeheron{
namespace commitment {

/**
 * Commitment with a blind factor
 * @param num
 * @param blind_factor
 * @return commitment
 */
safeheron::bignum::BN CreateComWithBlind(safeheron::bignum::BN &num, safeheron::bignum::BN &blind_factor);

/**
 * Commitment with a blind factor
 * @param point
 * @param blind_factor
 * @return commitment
 */
safeheron::bignum::BN CreateComWithBlind(curve::CurvePoint &point, safeheron::bignum::BN &blind_factor);

/**
 * Commitment with a blind factor
 * @param points
 * @param blind_factor
 * @return commitment
 */
safeheron::bignum::BN CreateComWithBlind(std::vector<curve::CurvePoint> &points, safeheron::bignum::BN &blind_factor);

/**
 * Create a commitment.
 * @param num
 * @return commitment
 */
safeheron::bignum::BN CreateCom(safeheron::bignum::BN &num);

/**
 * Create a commitment.
 * @param point
 * @return commitment
 */
safeheron::bignum::BN CreateCom(curve::CurvePoint &point);

/**
 * Create a commitment.
 * @param points
 * @return commitment
 */
safeheron::bignum::BN CreateCom(std::vector<curve::CurvePoint> &points);

}
}


#endif //CPP_MPC_COMMITMENT_H
