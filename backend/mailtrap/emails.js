import { mailtrapClient, sender } from "./mailtrap.config.js"; // This should stay the same
import { PASSWORD_RESET_REQUEST_TEMPLATE, PASSWORD_RESET_SUCCESS_TEMPLATE, VERIFICATION_EMAIL_TEMPLATE } from '../mailtrap/emailTemplates.js'

export const sendVerificationEmail = async (email, verificationToken) => {
    const recipient = [{ email }]

    try {
        const response = await mailtrapClient.send({
            from: sender,
            to: recipient,
            subject: "Verify your email",
            html: VERIFICATION_EMAIL_TEMPLATE.replace("{verificationCode}", verificationToken),
            category: "Email Verification"
        });
        console.log('Email Sent Successfully', response);
    } catch (error) {
        console.error(`Error sending verification`, error);
        throw new Error(`Error sending verification email: ${error}`);
    }
}


export const sendWelcomeEmail = async (email, name) => {
    const recipient = [{ email }];
    try {
        const response = await mailtrapClient.send({
            from: sender,
            to: recipient,
            template_uuid: "b8507d43-1940-4553-8823-b96677343b74",
            template_variables: {
                "company_info_name": "Textile Job Manager",
                "name": name,
                "company_info_address": "Tamil Nadu",
                "company_info_city": "Chenna",
                "company_info_zip_code": "600091",
                "company_info_country": "India"
            }
        })
        console.log("Email sent successfully");
    } catch (error) {

    }
}

export const sendPasswordResetEmail = async (email, resetURL) => {
    const recipient = [{ email }];
    try {
        const response = await mailtrapClient.send({
            from: sender,
            to: recipient,
            subject: "Reset Your Password",
            html: PASSWORD_RESET_REQUEST_TEMPLATE.replace("{resetURL}", resetURL),
            category: "Password Reset"
        })
        console.log(response);
    } catch (error) {
        console.log("Error sending password reset email", error);
        throw new error(`error sending Password reset email ${error}`)
    }
}

export const sendResetSuccessEmail = async (email) => {
    const recipient = [{ email }];
    try {
        const response = await mailtrapClient.send({
            from: sender,
            to: recipient,
            subject: "password Reset Successfull",
            html: PASSWORD_RESET_SUCCESS_TEMPLATE,
            category: "Password Reset"
        })
        console.log("Password reset email sent successfully", response);
    } catch (error) {
        console.log("Error sending Password reset success mail");
        throw new Error(`Error sending Password reset success mail: ${error}`)
    }
}