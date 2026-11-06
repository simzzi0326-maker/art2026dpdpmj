-- 실시간 미술 퀴즈(live.html)용 Supabase 설정
-- Supabase 대시보드 > SQL Editor > New query 에 이 파일 전체를 붙여 넣고 Run 을 누르세요.
-- 여러 번 실행해도 괜찮습니다.

create extension if not exists pgcrypto with schema extensions;

-- 방: 학생 누구나 읽을 수 있음. 바꾸는 건 아래 함수(선생님 PIN 확인)로만 가능.
create table if not exists public.quiz_rooms (
  code       text primary key,
  phase      text not null default 'lobby' check (phase in ('lobby','question','reveal','end')),
  idx        int  not null default 0,
  level      int  not null default 0 check (level between 0 and 3),
  round      int  not null default 1,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- 선생님 PIN(암호화해서 저장). 아무도 직접 읽을 수 없음.
create table if not exists public.quiz_room_secrets (
  code     text primary key references public.quiz_rooms(code) on delete cascade,
  pin_hash text not null
);

create table if not exists public.quiz_players (
  room       text not null references public.quiz_rooms(code) on delete cascade,
  round      int  not null,
  player_id  uuid not null,
  nickname   text not null check (char_length(nickname) between 1 and 12),
  joined_at  timestamptz not null default now(),
  primary key (room, round, player_id)
);

create table if not exists public.quiz_answers (
  room       text not null references public.quiz_rooms(code) on delete cascade,
  round      int  not null,
  player_id  uuid not null,
  q_index    int  not null,
  choice     text not null check (char_length(choice) <= 2),
  created_at timestamptz not null default now(),
  primary key (room, round, player_id, q_index)
);

alter table public.quiz_rooms        enable row level security;
alter table public.quiz_room_secrets enable row level security;
alter table public.quiz_players      enable row level security;
alter table public.quiz_answers      enable row level security;

drop policy if exists rooms_read   on public.quiz_rooms;
drop policy if exists players_read on public.quiz_players;
drop policy if exists players_join on public.quiz_players;
drop policy if exists answers_read on public.quiz_answers;
drop policy if exists answers_add  on public.quiz_answers;

create policy rooms_read   on public.quiz_rooms   for select to anon, authenticated using (true);
create policy players_read on public.quiz_players for select to anon, authenticated using (true);
create policy answers_read on public.quiz_answers for select to anon, authenticated using (true);

-- 지금 진행 중인 판에만 참여할 수 있음
create policy players_join on public.quiz_players for insert to anon, authenticated
  with check (exists (select 1 from public.quiz_rooms r
                      where r.code = quiz_players.room and r.round = quiz_players.round));

-- 지금 화면에 떠 있는 문제에, 정답 공개 전까지만 답할 수 있음(한 번만)
create policy answers_add on public.quiz_answers for insert to anon, authenticated
  with check (exists (select 1 from public.quiz_rooms r
                      where r.code = quiz_answers.room
                        and r.round = quiz_answers.round
                        and r.idx = quiz_answers.q_index
                        and r.phase = 'question'));

-- 선생님 PIN(학교에 하나). 방은 이 PIN을 아는 사람만 만들 수 있음. 아무도 직접 읽을 수 없음.
-- PIN 정하기/바꾸기는 이 파일에 적지 말고 SQL Editor에서 따로 실행하세요(저장소가 공개이므로):
--   insert into public.quiz_settings(id, teacher_pin_hash) values (1, extensions.crypt('여기에PIN', extensions.gen_salt('bf')))
--   on conflict (id) do update set teacher_pin_hash = excluded.teacher_pin_hash;
create table if not exists public.quiz_settings (
  id               int primary key default 1 check (id = 1),
  teacher_pin_hash text not null
);
alter table public.quiz_settings enable row level security;

-- 선생님: 방 만들기. 하루 지난 방은 이때 함께 지웁니다.
create or replace function public.quiz_create_room(p_pin text, p_level int default 0)
returns text language plpgsql security definer set search_path = public, extensions as $$
declare v_code text;
begin
  if not exists (select 1 from quiz_settings) then
    raise exception '선생님 PIN이 아직 설정되지 않았어요';
  end if;
  if p_pin is null or not exists (select 1 from quiz_settings s where s.teacher_pin_hash = crypt(p_pin, s.teacher_pin_hash)) then
    raise exception '선생님 PIN이 맞지 않아요';
  end if;
  delete from quiz_rooms where updated_at < now() - interval '1 day';
  loop
    v_code := lpad((floor(random() * 10000))::int::text, 4, '0');
    exit when not exists (select 1 from quiz_rooms where code = v_code);
  end loop;
  insert into quiz_rooms(code, level) values (v_code, coalesce(p_level, 0));
  insert into quiz_room_secrets(code, pin_hash) values (v_code, crypt(p_pin, gen_salt('bf')));
  return v_code;
end $$;

create or replace function public.quiz_check_pin(p_code text, p_pin text)
returns boolean language sql security definer set search_path = public, extensions as $$
  select exists (select 1 from quiz_room_secrets s
                 where s.code = p_code and s.pin_hash = crypt(p_pin, s.pin_hash));
$$;

-- 선생님: 진행 상태 바꾸기(문제 넘기기, 정답 공개, 새 판)
create or replace function public.quiz_control(p_code text, p_pin text, p_phase text, p_idx int, p_level int, p_round int)
returns void language plpgsql security definer set search_path = public, extensions as $$
begin
  if not quiz_check_pin(p_code, p_pin) then
    raise exception 'PIN이 맞지 않아요';
  end if;
  update quiz_rooms
     set phase = p_phase, idx = p_idx, level = p_level, round = p_round, updated_at = now()
   where code = p_code;
end $$;

revoke all on function public.quiz_check_pin(text, text) from public;
grant execute on function public.quiz_create_room(text, int) to anon, authenticated;
grant execute on function public.quiz_check_pin(text, text) to anon, authenticated;
grant execute on function public.quiz_control(text, text, text, int, int, int) to anon, authenticated;

-- 실시간 알림 켜기
do $$
begin
  begin alter publication supabase_realtime add table public.quiz_rooms;   exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.quiz_players; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.quiz_answers; exception when duplicate_object then null; end;
end $$;
