import assert from 'node:assert/strict';
import { test } from 'node:test';
import { EventStream, HttpClient, MoonSsoError, SseParser, type SseMessage } from '../../dist/index.js';

function parse(chunks: string[]): { msgs: SseMessage[]; parser: SseParser; retries: number[] } {
  const msgs: SseMessage[] = [];
  const retries: number[] = [];
  const parser = new SseParser((m) => msgs.push(m), (r) => retries.push(r));
  for (const c of chunks) {
    parser.feed(c);
  }
  return { msgs, parser, retries };
}

test('parses id, event, multi-line data and retry; ignores comments', () => {
  const { msgs, parser, retries } = parse([
    'retry: 4500\n\n',
    ': ping\n\n',
    'id: 7\nevent: user.updated\ndata: {"a":1,\ndata: "b":2}\n\n',
    'event: resync\ndata: {}\n\n',
  ]);
  assert.deepEqual(retries, [4500]);
  assert.equal(parser.retry, 4500);
  assert.equal(msgs.length, 2);
  assert.deepEqual(msgs[0], { event: 'user.updated', data: '{"a":1,\n"b":2}', lastEventId: '7', hasId: true });
  // id persists, but the frame had no id of its own
  assert.deepEqual(msgs[1], { event: 'resync', data: '{}', lastEventId: '7', hasId: false });
});

test('handles CRLF, CR and frames split at arbitrary positions', () => {
  const text = 'id: 1\r\nevent: a\r\ndata: x\r\n\r\nid: 2\rdata: y\r\rdata: z\n\n';
  for (let size = 1; size <= text.length; size++) {
    const chunks: string[] = [];
    for (let i = 0; i < text.length; i += size) {
      chunks.push(text.slice(i, i + size));
    }
    const { msgs } = parse(chunks);
    assert.deepEqual(
      msgs.map((m) => [m.event, m.data, m.lastEventId]),
      [
        ['a', 'x', '1'],
        ['message', 'y', '2'],
        ['message', 'z', '2'],
      ],
      `chunk size ${size}`,
    );
  }
});

test('frames without data are not dispatched; field without colon; leading space only stripped once', () => {
  const { msgs } = parse(['event: nothing\n\n', 'data\n\n', 'data:  two spaces\n\n', 'id: x\0y\ndata: q\n\n', 'unknown: 1\ndata: w\n\n']);
  assert.deepEqual(
    msgs.map((m) => [m.data, m.lastEventId]),
    [
      ['', ''],
      [' two spaces', ''],
      ['q', ''],
      ['w', ''],
    ],
  );
});

test('incomplete trailing frame is discarded at end of stream', () => {
  const { msgs, parser } = parse(['data: complete\n\n', 'data: partial']);
  parser.end();
  assert.equal(msgs.length, 1);
});

function sseResponse(body: string, status = 200): Response {
  return new Response(body, { status, headers: { 'Content-Type': 'text/event-stream' } });
}

test('EventStream resumes with Last-Event-ID, honours retry and refreshes on 401 and token_expired', async () => {
  const seen: { auth: string | null; last: string | null }[] = [];
  let n = 0;
  const http = new HttpClient({
    fetch: async (input, init) => {
      const h = new Headers(init?.headers);
      seen.push({ auth: h.get('Authorization'), last: h.get('Last-Event-ID') });
      n++;
      if (n === 1) {
        return sseResponse('retry: 10\n\nid: 5\nevent: user.updated\ndata: {"n":1}\n\n');
      }
      if (n === 2) {
        return new Response('{"error":"invalid_token"}', { status: 401 });
      }
      if (n === 3) {
        return sseResponse('id: 6\nevent: user.updated\ndata: {"n":2}\n\nevent: token_expired\ndata: {}\n\n');
      }
      return sseResponse('id: 7\nevent: user.updated\ndata: {"n":3}\n\n');
    },
  });
  let tokenNo = 0;
  const forced: boolean[] = [];
  const messages: string[] = [];
  let resolveDone!: () => void;
  const done = new Promise<void>((r) => {
    resolveDone = r;
  });
  const stream = new EventStream({
    http,
    url: 'https://sso.test/api/v1/me/events',
    getAccessToken: async (o) => {
      forced.push(Boolean(o.force));
      if (o.force || tokenNo === 0) {
        tokenNo++;
      }
      return `tok${tokenNo}`;
    },
    onMessage: (m) => {
      messages.push(`${m.lastEventId}:${m.event}`);
      if (m.lastEventId === '7') {
        resolveDone();
      }
    },
    minDelayMs: 1,
    maxDelayMs: 2,
  });
  stream.start();
  await done;
  await stream.stop();
  assert.deepEqual(messages, ['5:user.updated', '6:user.updated', '6:token_expired', '7:user.updated']);
  assert.equal(seen[0]?.last, null);
  assert.equal(seen[1]?.last, '5'); // reconnect resumes after event 5
  assert.equal(seen[1]?.auth, 'Bearer tok1');
  assert.equal(seen[2]?.auth, 'Bearer tok2'); // 401 → forced refresh → retried
  assert.equal(seen[3]?.auth, 'Bearer tok3'); // token_expired → refresh → immediate reconnect
  assert.equal(seen[3]?.last, '6');
  assert.ok(forced.filter(Boolean).length >= 2);
});

test('EventStream stops on fatal errors', async () => {
  const errors: unknown[] = [];
  const stream = new EventStream({
    http: new HttpClient({ fetch: async () => new Response('{"error":"insufficient_scope"}', { status: 403 }) }),
    url: 'https://sso.test/api/v1/me/events',
    getAccessToken: async () => 't',
    onMessage: () => undefined,
    onError: (e) => errors.push(e),
    minDelayMs: 1,
    maxDelayMs: 1,
  });
  stream.start();
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(stream.isRunning, false);
  assert.equal(errors.length, 1);
  assert.ok(errors[0] instanceof MoonSsoError && errors[0].status === 403);
  await stream.stop();
});
