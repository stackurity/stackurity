import { LeaksView } from "../components/Leaks";
import { PageHeader } from "../components/ui";

export function LeaksPage() {
  return (
    <>
      <PageHeader
        title="Leaked keys"
        sub="Keys, tokens and passwords found written in files on your servers, applications and repositories. Stackurity never stores the values: each row names the kind of key, where it is and why that matters."
      />
      <LeaksView />
    </>
  );
}
