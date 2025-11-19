# SRP Requirements

OCP Security Workgroup

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
</table>

## Introduction

This document shows what information we want to see from Security Review Providers to consider their application as OCP S.A.F.E. review providers. If you are interested in applying, please send us a document with answers to all the questions and we will review your application. If you are approved, you will have to join the OCP and pay the membership fee in order to be added as OCP S.A.F.E. review provider.

## Technical expertise

We need to see evidence that you are capable of performing reviews covering the scopes outlined [here](review_areas.md). The more evidence you can provide the better. This is the most important part of considering your application. We understand that it is difficult to provide evidence due to NDAs. However, without sufficient evidence we have no way to judge whether you are capable of performing reviews to a high standard and will therefore not admit you to the program.

These items can be suitable evidence, but we are open to anything you think might be helpful:

1. Appropriately-redacted reports of real engagements
2. Public tools you developed, e.g. GitHub links
3. Blog posts, white papers and other public documents
4. Descriptions of internal tools you have
5. Descriptions of physical facilities/equipment/tools, e.g. for fault injection and side-channel analysis

## Business processes

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

## Code of Conduct

Please confirm that your organization will adhere to the following code of conduct for the duration of you being an OCP S.A.F.E. review provider.

1. We will not sell vulnerabilities or exploits to entities other than the organizations responsible for securing the respective product.
2. We will disclose all affiliations that might appear to be conflicts of interest to the OCP S.A.F.E. leadership, as well as the vendor before starting a review. For example affiliations with exploit sellers, law enforcement, military and intelligence.
3. We will disclose any relationship we have with the vendor, other than performing security reviews, to the OCP S.A.F.E. leadership before starting a review.
