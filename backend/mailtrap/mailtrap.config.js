import { MailtrapClient as MailtrapAPI } from "mailtrap"; // Renaming the import
import dotenv from 'dotenv';

dotenv.config();

export const mailtrapClient = new MailtrapAPI({ // Renaming the export
  endpoint: process.env.MAILTRAP_ENDPOINT,
  token: process.env.MAILTRAP_TOKEN,
});

export const sender = {
  email: "mailtrap@demomailtrap.com",
  name: "sajeevan"
}
