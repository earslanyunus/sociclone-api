import { Resend } from 'resend';

const resend = new Resend(process.env.MAIL_PASS);

export const sendOTPEmail = async (to: string, otp: string) => {
    const { data, error } = await resend.emails.send({
        from: process.env.MAIL_USER as string,
        to: to,
        subject: 'OTP Verification',
        html: `Your OTP code is: ${otp}.`
          });
    
      if (error) {
        return console.error({ error });
      }
    
      console.log({ data });
  };

