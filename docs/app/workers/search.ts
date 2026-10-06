import { HashError } from "@agntn/hashes";
import { hashDigestSearch, type DigestSearch, type HashDigestSearchParams } from "#tool-operations";

/** What the playground hears from a search: the running count, then the answer or the refusal. */
export type SearchMessage =
  | { type: "progress"; tried: number; total: number }
  | { type: "done"; details: DigestSearch; text: string }
  | { type: "error"; name: string; message: string };

/**
 * Sends one message to the page.
 *
 * @param {SearchMessage} message - The count, the answer or the refusal.
 */
function send(message: SearchMessage) {
  postMessage(message);
}

/** One search per message. The page ends a stale one by terminating this worker, not by asking. */
addEventListener("message", (event: MessageEvent<HashDigestSearchParams>) => {
  try {
    const result = hashDigestSearch(event.data, (tried, total) => {
      send({ type: "progress", tried, total });
    });
    send({ type: "done", details: result.details, text: result.content[0]!.text });
  } catch (error) {
    if (!(error instanceof HashError)) throw error;
    send({ type: "error", name: error.name, message: error.message });
  }
});
