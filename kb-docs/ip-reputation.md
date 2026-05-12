## IP Reputation Rule Groups

### AWSManagedRulesAmazonIpReputationList (WCU: 25)
Contains three rules:
- `AWSManagedIPReputationList` (default Block): known malicious IPs from Amazon threat intelligence (MadPot). Generally safe to keep at default.
- `AWSManagedReconnaissanceList` (default Block): IPs performing reconnaissance against AWS resources. Generally safe to keep at default.
- `AWSManagedIPDDoSList` (default **Count**): IPs identified as participating in DDoS activities, including open proxies and potentially some residential proxies that are exploited as DDoS relay points

AWSManagedIPDDoSList defaults to Count because these IPs may belong to legitimate users whose devices were temporarily compromised — blocking them outright would cause false positives.

**Relationship with AntiDDoS AMR**: AntiDDoS AMR has built-in capability to handle IPs on the ManagedIPDDoSList. When AntiDDoS AMR is deployed, AWSManagedIPDDoSList is not needed — AMR subsumes its functionality. However, if the user does not deploy AntiDDoS AMR, AWSManagedIPDDoSList at default Count only adds a label without taking action. A downstream rule (e.g., a rate-based rule with the DDoS IP label as scope-down) is needed to make it effective.

### AWSManagedRulesAnonymousIpList (WCU: 50)
- `AnonymousIPList` (default Block): TOR nodes, temporary proxies, masking services
- `HostingProviderIPList` (default Block): cloud hosting and web hosting provider IPs

**HostingProviderIPList outdated assumption**: This rule assumes legitimate users don't originate from cloud platforms. This is increasingly false — many enterprises route traffic through cloud-based proxies, VPNs, or SaaS gateways, and many websites serve both enterprise and consumer traffic on the same domain. Default Block frequently causes false positives. Best practice: override to **Count** and optionally use the label for downstream rate limiting. Override to Allow is dangerous — it lets cloud-hosted attack traffic bypass all subsequent rules.

