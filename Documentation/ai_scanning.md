# AI scanning requirement

In addition to a regular human review, review providers are expected to use AI (an LLM) to perform a security review with the issues triaged by the review provider. The review must be performed using the latest version (at the time the review starts) of one of the following models:
*   Anthropic Opus
*   Gemini Pro
*   OpenAI GPT codex
This list will be regularly updated.

The review must be performed by a suitable harness for orchestration. Without an appropriate harness a review often goes off-track and does not look at all files. For now, the review provider may choose something they consider suitable, including their own tools. We can recommend [Arm Metis](https://github.com/arm/metis). We expect that over time more tools will be publicized and we will update this recommendation.

Using the review provider's AI subscription or the vendor giving the review provider access to their subscription for the project are both acceptable. IP can be protected by setting up a subscription with suitable terms that exclude the data from being used for training. Even if the vendor's access is used, the review provider must still run the actual AI tool themselves, it is not sufficient for the vendor to hand them the output.

This AI review must be performed in addition to, rather than instead of, a regular review by a security expert. What we have seen so far is that AI reviews find different issues from traditional reviews, rather than the same ones, so this increases coverage.

This requirement is optional, but strongly recommended, until 2027-01-01, at which time it becomes mandatory. This should give review providers and vendors time to set up suitable AI tools and processes.
