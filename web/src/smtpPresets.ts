/*
 * Common mail providers for "use your own mail server": picking one fills
 * the SMTP host, port and encryption. Shared by onboarding and Settings.
 */

export interface SmtpVariant {
  /** Shown in the region select. */
  label: string;
  host: string;
}

export interface SmtpPreset {
  id: string;
  label: string;
  port: number;
  tls: "starttls" | "tls";
  /** Fixed username, when the provider uses one. */
  username?: string;
  /** Where to get the credentials, one line. */
  note: string;
  /** Hosts to choose from (region / data centre); the first is the default. */
  variants: SmtpVariant[];
  variantLabel?: string;
}

const SES_REGIONS = [
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2",
  "ca-central-1",
  "eu-west-1",
  "eu-west-2",
  "eu-west-3",
  "eu-central-1",
  "eu-north-1",
  "eu-south-1",
  "ap-south-1",
  "ap-southeast-1",
  "ap-southeast-2",
  "ap-northeast-1",
  "ap-northeast-2",
  "ap-northeast-3",
  "sa-east-1",
];

export const SMTP_PRESETS: SmtpPreset[] = [
  {
    id: "ses",
    label: "Amazon SES",
    port: 587,
    tls: "starttls",
    note: "SES console → SMTP settings → Create SMTP credentials. The From address must be a verified identity.",
    variants: SES_REGIONS.map((r) => ({ label: r, host: `email-smtp.${r}.amazonaws.com` })),
    variantLabel: "Region",
  },
  {
    id: "sendgrid",
    label: "SendGrid",
    port: 587,
    tls: "starttls",
    username: "apikey",
    note: "Password: a SendGrid API key with Mail Send permission.",
    variants: [{ label: "Default", host: "smtp.sendgrid.net" }],
  },
  {
    id: "postmark",
    label: "Postmark",
    port: 587,
    tls: "starttls",
    note: "Username and password: your Server API token.",
    variants: [{ label: "Default", host: "smtp.postmarkapp.com" }],
  },
  {
    id: "mailgun",
    label: "Mailgun",
    port: 587,
    tls: "starttls",
    note: "Sending → Domain settings → SMTP credentials.",
    variants: [
      { label: "US", host: "smtp.mailgun.org" },
      { label: "EU", host: "smtp.eu.mailgun.org" },
    ],
    variantLabel: "Region",
  },
  {
    id: "zeptomail",
    label: "ZeptoMail",
    port: 587,
    tls: "starttls",
    username: "emailapikey",
    note: "Password: a Send Mail token from your Mail Agent → SMTP.",
    variants: [
      { label: "Global", host: "smtp.zeptomail.com" },
      { label: "India data centre", host: "smtp.zeptomail.in" },
    ],
    variantLabel: "Data centre",
  },
  {
    id: "gmail",
    label: "Gmail / Google Workspace",
    port: 587,
    tls: "starttls",
    note: "Username: the full address. Password: an app password (needs 2-Step Verification).",
    variants: [{ label: "Default", host: "smtp.gmail.com" }],
  },
];

/** The preset (and variant) a host belongs to, for editing an existing channel. */
export function presetForHost(host: string): { preset: SmtpPreset; variant: number } | null {
  const h = host.trim().toLowerCase();
  for (const p of SMTP_PRESETS) {
    const i = p.variants.findIndex((v) => v.host === h);
    if (i >= 0) return { preset: p, variant: i };
  }
  return null;
}
