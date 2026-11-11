# LinkedIn post: November Collaborative Testing (DRAFT)

**Status: draft for review. Nothing has been posted.** This replaces an earlier five-post set that was rejected as generic and that credited some firms to the wrong use case. Voice: OHIA ("we"). Audience: dental and health IT vendors (call to action) and policymakers.

---

When a pediatric dentist refers a child to another dentist for treatment, the referral, the records and the insurance approval still depend on a lot of manual work. At our recent testing event, we took that on, in a use case defined with DentaQuest and the American Dental Association.

Conduit, ToothApps, Patterson, Dentistry.One and MyDigiRecords brought working software, and together we tested on FHIR using synthetic data. A dentist accepted the referral, reviewed the documentation that came with it, and closed the loop. The missing piece is prior authorization, and DentaQuest told us it expects to deliver three prior authorization APIs in the next few weeks. When they arrive, we will be able to automate this referral, and DentaQuest has agreed to test with us again as soon as they do.

The second scenario matters especially for rural health. A teledentistry visit can reach a patient who lives far from any dentist, but only if that patient's information and images can follow them to the practice that will treat them. We showed that working as a real integration, with data moving live from a teledentistry visit to a dentist using ARex, an emerging specification for sharing images and other content.

Both scenarios were built on standards that exist today along with emerging ones like ARex, which gives the field a path to production, and to a standard everyone can share. Full end-to-end prior authorization and patient access are next.

The test data and test server we used are open: if you build dental or payer software, bring it, and if you make policy, come see what already works.

oralhealthalliance.net | oralhealth.atlassian.net

#FHIR #OralHealth

---

## Review before posting

1. **Approvals.** Every named organization (Conduit, ToothApps, Patterson, Dentistry.One, MyDigiRecords, DentaQuest, the ADA) should approve its mention. DentaQuest should approve the sentence about its prior authorization APIs and the further test. The ADA should approve being named as helping to define the use case.
2. **"In the next few weeks"** is DentaQuest's stated plan, with no date. Recheck it on the day of posting.
3. **"A real integration"** is the product owner's statement. It is not something the repositories can confirm.
4. **ARex is a draft specification.** The post calls it emerging and claims no conformance. "A path to production, and to a standard" is the owner's framing and does not say the work is ready for production.
5. **Open data and server.** The synthetic test data is public. The test server needs a token, and the guided tests and teaching site are not built yet. Change the last paragraph if "open" overstates what a reader can use on the day.
6. **Links.** Neither web address has been checked.
7. **Framing, not test results:** "the referral, the records and the insurance approval still depend on a lot of manual work" and "matters especially for rural health" are the owner's points, put in plain words.

## Where each claim comes from

| Claim | Source |
|---|---|
| Pediatric referral needs a lot of manual work today; it can be automated once the prior authorization APIs are delivered | Product owner |
| Use case defined with DentaQuest and the ADA | Product owner (the ADA helped with both use cases, DentaQuest with the Medicaid one) |
| Conduit, ToothApps, Patterson, Dentistry.One and MyDigiRecords brought working software | Product owner (the post lists all five without splitting them by use case) |
| A dentist accepted the referral, reviewed its documentation and closed the loop | Product owner |
| DentaQuest: three prior authorization APIs in the next few weeks, and another test once available | Product owner |
| Teledentistry matters for rural health; a real integration moved data live using ARex | Product owner |
| Testing used synthetic data; ARex is a draft specification | Test data repository README; ARex draft v0.2.0 |
| Next steps: end-to-end prior authorization and patient access | Product owner |
| Call-to-action addresses | Product owner (not checked) |
