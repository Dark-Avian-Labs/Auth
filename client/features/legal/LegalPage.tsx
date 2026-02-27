import { GlassCard } from '../../components/ui/GlassCard';

export function LegalPage() {
  return (
    <div className="mx-auto max-w-5xl">
      <GlassCard className="p-8">
        <h1 className="text-2xl font-semibold text-foreground">Legal</h1>

        <section className="mt-6 space-y-2 text-sm text-muted">
          <h2 className="text-lg font-semibold text-foreground">Contact</h2>
          <p>Lutz Schwemer Panchez</p>
          <p>Holsteiner Str. 1</p>
          <p>21465 Reinbek</p>
          <p>Phone: +49 176 72439032</p>
          <p>E-Mail: shark@shark5060.net</p>
        </section>

        <section className="mt-8 space-y-3 text-sm text-muted">
          <h2 className="text-lg font-semibold text-foreground">
            Information Section 5 DDG
          </h2>
          <h3 className="text-base font-semibold text-foreground">
            Liability for Content
          </h3>
          <p>
            The content of this website was created with great care. However, no
            guarantee is made for correctness, completeness, or timeliness. As a
            service provider, we are responsible for our own content under
            applicable laws.
          </p>
          <p>
            According to Sections 8 to 10 TMG, we are not obliged to monitor
            transmitted or stored third-party information or to investigate
            circumstances indicating illegal activity. Obligations to remove or
            block the use of information under general laws remain unaffected.
            Liability in this regard is possible only from the point in time at
            which a concrete legal violation becomes known. Upon becoming aware
            of legal violations, such content will be removed immediately.
          </p>

          <h3 className="pt-2 text-base font-semibold text-foreground">
            Liability for Links
          </h3>
          <p>
            This website contains links to external third-party websites whose
            content is outside our control. Therefore, no liability can be
            assumed for external content. The respective provider or operator of
            linked pages is always responsible for their content.
          </p>
          <p>
            Linked pages were checked for potential legal violations at the time
            of linking. Illegal content was not identifiable at that time.
            Permanent content control of linked pages is unreasonable without
            concrete indication of a legal violation. If violations become
            known, such links will be removed immediately.
          </p>

          <h3 className="pt-2 text-base font-semibold text-foreground">
            Copyright
          </h3>
          <p>
            Content and works created by the site operators are subject to
            German copyright law. Reproduction, editing, distribution, and any
            use outside copyright limits require prior written consent of the
            respective author or creator.
          </p>
          <p>
            Downloads and copies of this page are permitted for private,
            non-commercial use only. Where content on this page was not created
            by the operator, third-party copyrights are respected and marked
            accordingly. If you become aware of a copyright infringement, please
            inform us. Such content will be removed immediately once violations
            become known.
          </p>
        </section>

        <section className="mt-8 space-y-3 text-sm text-muted">
          <h2 className="text-lg font-semibold text-foreground">
            Privacy Policy
          </h2>
          <h3 className="text-base font-semibold text-foreground">Preamble</h3>
          <p>
            This privacy policy explains what personal data is processed, for
            what purposes, and to what extent. It applies to all data processing
            carried out in connection with our services and online presence.
          </p>
          <p>Last updated: December 29, 2025.</p>

          <h3 className="pt-2 text-base font-semibold text-foreground">
            Responsible Person
          </h3>
          <p>Lutz Schwemer Panchez, Holsteiner Str. 1, 21465 Reinbek</p>
          <p>Phone: +49 176 72439032</p>
          <p>E-Mail: shark@shark5060.net</p>

          <h3 className="pt-2 text-base font-semibold text-foreground">
            Types of Data Processed
          </h3>
          <ul className="list-disc space-y-1 pl-5">
            <li>Usage data</li>
            <li>Metadata, communication, and process data</li>
            <li>Log data</li>
          </ul>

          <h3 className="pt-2 text-base font-semibold text-foreground">
            Purposes of Processing
          </h3>
          <ul className="list-disc space-y-1 pl-5">
            <li>Security measures</li>
            <li>Provision and usability of online services</li>
            <li>Information technology infrastructure</li>
          </ul>

          <h3 className="pt-2 text-base font-semibold text-foreground">
            Legal Basis
          </h3>
          <p>
            Processing is based on GDPR legal bases, in particular legitimate
            interests under Art. 6(1)(f) GDPR where applicable.
          </p>

          <h3 className="pt-2 text-base font-semibold text-foreground">
            Security Measures
          </h3>
          <p>
            Appropriate technical and organizational measures are implemented to
            ensure a level of security appropriate to risk, including
            confidentiality, integrity, and availability controls.
          </p>
          <p>
            Online transmissions are protected using TLS/SSL (HTTPS) encryption.
          </p>

          <h3 className="pt-2 text-base font-semibold text-foreground">
            Transfer of Personal Data
          </h3>
          <p>
            Data may be transferred to service providers when necessary. In such
            cases, legal requirements are respected and suitable agreements are
            used to protect data.
          </p>

          <h3 className="pt-2 text-base font-semibold text-foreground">
            Storage and Deletion
          </h3>
          <p>
            Personal data is deleted when consent is withdrawn or legal basis no
            longer applies, unless legal retention obligations require longer
            storage.
          </p>
          <ul className="list-disc space-y-1 pl-5">
            <li>10 years for books and records under tax/commercial law</li>
            <li>8 years for accounting documents such as invoices</li>
            <li>6 years for other business documents</li>
            <li>3 years for typical contractual/warranty claims</li>
          </ul>

          <h3 className="pt-2 text-base font-semibold text-foreground">
            Rights of Data Subjects
          </h3>
          <ul className="list-disc space-y-1 pl-5">
            <li>Right to object</li>
            <li>Right to withdraw consent</li>
            <li>Right of access</li>
            <li>Right to rectification</li>
            <li>Right to erasure/restriction</li>
            <li>Right to data portability</li>
            <li>Right to lodge a complaint with a supervisory authority</li>
          </ul>

          <h3 className="pt-2 text-base font-semibold text-foreground">
            Provision of Online Service and Web Hosting
          </h3>
          <p>
            User data (including IP address and log data) is processed to
            provide online services, ensure stability, and apply security
            measures.
          </p>
          <p>
            Server log files may include requested pages/files, timestamp,
            transferred data, browser details, OS, referrer URL, and IP address.
            Log data is generally retained for up to 30 days unless needed as
            evidence.
          </p>

          <h3 className="pt-2 text-base font-semibold text-foreground">
            Hosting Provider
          </h3>
          <p>netcup GmbH, Daimlerstrasse 25, 76185 Karlsruhe, Germany</p>
          <p>
            Website:{' '}
            <a
              className="text-foreground underline underline-offset-2"
              href="https://www.netcup.de/"
              target="_blank"
              rel="noreferrer"
            >
              https://www.netcup.de/
            </a>
          </p>
          <p>
            Privacy policy:{' '}
            <a
              className="text-foreground underline underline-offset-2"
              href="https://www.netcup.de/kontakt/datenschutzerklaerung.php"
              target="_blank"
              rel="noreferrer"
            >
              https://www.netcup.de/kontakt/datenschutzerklaerung.php
            </a>
          </p>
          <p>
            Data processing agreement:{' '}
            <a
              className="text-foreground underline underline-offset-2"
              href="https://helpcenter.netcup.com/de/wiki/general/avv/"
              target="_blank"
              rel="noreferrer"
            >
              https://helpcenter.netcup.com/de/wiki/general/avv/
            </a>
          </p>

          <h3 className="pt-2 text-base font-semibold text-foreground">
            Changes and Updates
          </h3>
          <p>
            This privacy policy is reviewed and updated whenever data processing
            changes require it.
          </p>

          <h3 className="pt-2 text-base font-semibold text-foreground">
            Copyright for Third-Party Content
          </h3>
          <ul className="list-disc space-y-1 pl-5">
            <li>Header font "Inter" - The Inter Project Authors</li>
            <li>Profile Icons - Vecteezy.com</li>
            <li>General legal text - Kanzlei Hasselbach</li>
            <li>GDPR text - Dr. Thomas Schwenke</li>
          </ul>
        </section>
      </GlassCard>
    </div>
  );
}
