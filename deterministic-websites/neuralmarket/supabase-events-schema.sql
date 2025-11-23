-- Events table for comprehensive user behavior tracking
-- Captures all user interactions: clicks, form inputs, navigation, scroll, mouse movement

create table if not exists events (
  id bigserial primary key,
  base_url text not null,
  event_type text not null,
  event_data jsonb,
  session_id uuid,
  user_id text,
  attacker_id text,
  timestamp timestamptz not null,
  created_at timestamptz default now()
);

-- Indexes for efficient querying
create index if not exists idx_events_session on events(session_id);
create index if not exists idx_events_type on events(event_type);
create index if not exists idx_events_timestamp on events(timestamp);
create index if not exists idx_events_attacker on events(attacker_id);
create index if not exists idx_events_base_url on events(base_url);

-- GIN index for JSONB queries on event_data
create index if not exists idx_events_data on events using gin(event_data);

-- Comments for documentation
comment on table events is 'Tracks all user interactions and behavior on the honeypot site';
comment on column events.base_url is 'Base URL of the honeypot deployment';
comment on column events.event_type is 'Type of event: page_view, user_click, user_submit, user_change, user_focus, user_input, mouse_position, scroll_depth';
comment on column events.event_data is 'JSON data containing event-specific details (element info, coordinates, etc)';
comment on column events.session_id is 'Unique session ID generated client-side, persists across page views';
comment on column events.user_id is 'User ID if authenticated (stored in localStorage after login/signup)';
comment on column events.attacker_id is 'IP address of the attacker/user';
comment on column events.timestamp is 'Client-side timestamp when event occurred';
comment on column events.created_at is 'Server-side timestamp when event was logged';
