from bbot.modules.templates.subdomain_enum import subdomain_enum


class thc(subdomain_enum):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "description": "Query THC's IP API for subdomains",
        "created_date": "2025-04-28",
        "author": "@SystemNatalie",
    }

    base_url = "https://ip.thc.org/api/v1/lookup/subdomains"
    reject_wildcards = False
    page_size = 250

    async def handle_event(self, event):
        query = self.make_query(event)
        page_state = ""
        while True:
            r = await self.api_request(
                self.base_url,
                method="POST",
                json={"domain": query, "page_state": page_state, "limit": self.page_size},
            )
            if r is None:
                break
            j = r.json()
            if not isinstance(j, dict):
                break
            domains = j.get("domains", [])
            if not domains:
                break
            for entry in domains:
                hostname = entry.get("domain", "") if isinstance(entry, dict) else entry
                if hostname:
                    try:
                        hostname = self.helpers.validators.validate_host(hostname)
                    except ValueError as e:
                        self.verbose(e)
                        continue
                    if hostname and hostname.endswith(f".{query}") and not hostname == event.data:
                        await self.emit_event(
                            hostname,
                            "DNS_NAME",
                            event,
                            abort_if=self.abort_if,
                            context=f'{{module}} searched THC IP API for "{query}" and found {{event.type}}: {{event.data}}',
                        )
            page_state = j.get("next_page_state", "")
            if not page_state:
                break
