/* eslint-disable */
import axios from 'axios';
import { showAlert } from './alerts';
const stripe = Stripe(
  `pk_test_51SI5jQFqkHd5UgCdOiMpZISS4gwXjCoghKSUOCkr0xNTGLoOApuXJBH23Mdahch4YhINlcd1Lb4XZtHPAr115YR700Nso8sVyo`,
);

export const bookTour = async (tourId) => {
  try {
    // 1) Get checkout session from API
    const session = await axios.get(
      `http://127.0.0.1:8000/api/v1/bookings/checkout-session/${tourId}`,
    );
    // 2) Redirect to Stripe checkout
    await stripe.redirectToCheckout({
      sessionId: session.data.session.id,
    });
  } catch (err) {
    console.error(err);
    showAlert('error', err);
  }
};
