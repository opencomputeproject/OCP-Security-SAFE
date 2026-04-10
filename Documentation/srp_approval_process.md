# SRP Approval Process

**Revision History**

<table>
  <tr>
   <td><strong>Revision</strong>
   </td>
   <td><strong>Date</strong>
   </td>
   <td><strong>Guiding Contributor(s)</strong>
   </td>
   <td><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>1.0
   </td>
   <td>Sep, 2023
   </td>
   <td>IOA, Microsoft
   </td>
   <td>Initial draft
   </td>
  </tr>
  <tr>
   <td>1.1
   </td>
   <td>Nov, 2025
   </td>
   <td>Nick Hummel
   </td>
   <td>Simplification
   </td>
  </tr>
  <tr>
   <td>1.2
   </td>
   <td>Apr, 2026
   </td>
   <td>Nick Hummel
   </td>
   <td>Added rules on approval/dismissal
   </td>
  </tr>
</table>

## Introduction

This document sets the rules for approval and dismissal of security review providers.

## Initial approval

To be approved as security review provider, please provide to us what is listed under [Requirements](#requirements). S.A.F.E. leadership will review your application. If you are admitted you will have to join the OCP and pay the membership fee (if not already a member).

From the date you are approved as review provider, you have 9 months to have a short-form report for a review you conducted submitted to the repository. If you fail to do so, you will be dismissed from the program again. This is to avoid having providers sign up just to get another endorsement for marketing purposes with no intention of conducting reviews. Exceptions can be made case by case if there are good reasons.

## Continuous approval

To remain a security review provider:

*   You must continue to meet the [requirements](#requirements).
*   You must have a short-form report for a review you conducted submitted to the repository at least every 2 years on a rolling basis. Failure to do results in dismissal. Exceptions can be made case by case if there are good reasons. For providers that were already approved before this rule came into effect (2026-04-09), it will apply starting from 2026-10-01.

## Quality control

We encourage product vendors and consumers of reports to provide feedback on security review providers to S.A.F.E. leadership. If there is a perceived sufficient amount of negative feedback on a review provider, the Technical Advisory Committee will vote on their dismissal.

## Reapproval

*   For dismissals due to failure to have a short-form report submitted, the hurdle is not high. Simply ensure that you have a vendor you will work with lined up this time and explain this with your reapplication.
*   For dismissals due to reported quality concerns, the hurdle for readmission is high. You would have to demonstrate that the quality of your work has significantly increased. Without strong evidence to this end no reapproval is possible.

## Requirements

### Technical expertise

We need to see evidence that you are capable of performing reviews covering the scopes outlined [here](review_areas.md). The more evidence you can provide the better. This is the most important part of considering your application. We understand that it is difficult to provide evidence due to NDAs. However, without sufficient evidence we have no way to judge whether you are capable of performing reviews to a high standard and will therefore not admit you to the program.

These items can be suitable evidence, but we are open to anything you think might be helpful:

1. Appropriately-redacted reports of real engagements
2. Public tools you developed, e.g. GitHub links
3. Blog posts, white papers and other public documents
4. Descriptions of internal tools you have
5. Descriptions of physical facilities/equipment/tools, e.g. for fault injection and side-channel analysis

### Business processes

If you are SOC 2 or ISO27001 accredited you can tell us that instead of responding to the questions here.

1. Do you have an Information Security Policy defined and if so can you share that with us?
2. Do all your employees receive IT security training when joining and regularly thereafter?
3. Is there at least one person designated to ensure IT security in your organization? What qualifies them for this?
4. How do you ensure source code and other confidential data you receive from vendors does not leak? How do you ensure confidential data is fully erased after an engagement?
5. What protections do you have in place against insiders stealing confidential data?
6. What does your screening process for potential employees entail?
7. What access control systems do you have in place? How do you ensure access is fully revoked when an employee leaves?
8. What endpoint protection and intrusion detection systems do you have?
9. How do you plan to protect the private key that will be used for signing your OCP S.A.F.E. reports?
10. Is all data you store encrypted at rest?
11. What physical security do your offices have?
12. Are all your computers configured to lock their screen after a certain amount of time has elapsed?
13. Do all your systems require at least two factor authentication for access?
14. How do you monitor your computers and other devices for public vulnerabilities and ensure they get patched in a timely manner?
15. What logging systems do you have in place to make sure you can analyze what happened in case of a potential security breach?

### Code of Conduct

Please confirm that your organization will adhere to the following code of conduct for the duration of you being an OCP S.A.F.E. review provider.

1. We will not sell vulnerabilities or exploits to entities other than the organizations responsible for securing the respective product.
2. We will disclose all affiliations that might appear to be conflicts of interest to the OCP S.A.F.E. leadership, as well as the vendor before starting a review. For example affiliations with exploit sellers, law enforcement, military and intelligence.
3. We will disclose any relationship we have with the vendor, other than performing security reviews, to the OCP S.A.F.E. leadership before starting a review.
