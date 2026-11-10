-- 미술사 대모험(game.html) 진행 상황 저장용 Supabase 설정
-- Supabase 대시보드 > SQL Editor > New query 에 이 파일 전체를 붙여 넣고 Run 을 누르세요.
-- 여러 번 실행해도 괜찮습니다. 실시간 퀴즈(live-quiz.sql)를 먼저 실행해 두어야 합니다(선생님 PIN을 함께 씀).
--
-- 학생은 "이름 + 4자리 비밀번호"로 자기 진행 상황(아이템, 퀴즈, 만든 탑, 외형 등)을 저장하고
-- 어느 기기에서든 이어 할 수 있습니다. 표는 아무도 직접 읽거나 쓸 수 없고, 아래 함수로만 다룹니다.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.game_progress (
  name       text primary key check (char_length(name) between 1 and 12),
  pw_hash    text not null,
  prog       jsonb not null default '{}'::jsonb,
  look       jsonb not null default '{}'::jsonb,
  last_room  text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.game_progress enable row level security;
-- 정책을 만들지 않으므로 학생이 표를 직접 읽거나 바꿀 수 없습니다.

-- 학생: 불러오기. 처음 쓰는 이름이면 status = 'new'
create or replace function public.game_load(p_name text, p_pw text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare r game_progress;
begin
  select * into r from game_progress where name = p_name;
  if not found then return jsonb_build_object('status','new'); end if;
  if p_pw is null or r.pw_hash <> crypt(p_pw, r.pw_hash) then return jsonb_build_object('status','wrong'); end if;
  return jsonb_build_object('status','ok','prog',r.prog,'look',r.look);
end $$;

-- 학생: 저장하기. 처음이면 새로 만들고, 있으면 비밀번호가 맞을 때만 덮어씁니다.
create or replace function public.game_save(p_name text, p_pw text, p_prog jsonb, p_look jsonb, p_room text)
returns text language plpgsql security definer set search_path = public, extensions as $$
declare r game_progress;
begin
  if p_name is null or char_length(p_name) not between 1 and 12 then raise exception '이름은 1~12글자로 적어 주세요'; end if;
  if p_pw is null or p_pw !~ '^[0-9]{4}$' then raise exception '비밀번호는 숫자 4자리예요'; end if;
  if octet_length(coalesce(p_prog,'{}'::jsonb)::text) + octet_length(coalesce(p_look,'{}'::jsonb)::text) > 300000 then
    raise exception '저장할 내용이 너무 커요';
  end if;
  select * into r from game_progress where name = p_name for update;
  if not found then
    insert into game_progress(name, pw_hash, prog, look, last_room)
    values (p_name, crypt(p_pw, gen_salt('bf')), coalesce(p_prog,'{}'::jsonb), coalesce(p_look,'{}'::jsonb), nullif(p_room,''));
    return 'created';
  end if;
  if r.pw_hash <> crypt(p_pw, r.pw_hash) then raise exception '비밀번호가 맞지 않아요'; end if;
  update game_progress
     set prog = coalesce(p_prog, prog), look = coalesce(p_look, look),
         last_room = coalesce(nullif(p_room,''), last_room), updated_at = now()
   where name = p_name;
  return 'saved';
end $$;

-- 선생님 PIN 확인 (live-quiz.sql 의 quiz_settings 를 함께 씀)
create or replace function public.game_teacher_ok(p_pin text)
returns boolean language sql security definer set search_path = public, extensions as $$
  select p_pin is not null and exists (select 1 from quiz_settings s where s.teacher_pin_hash = crypt(p_pin, s.teacher_pin_hash));
$$;

-- 선생님: 학생 진행 상황 보기. p_room 을 주면 그 방에 마지막으로 들어온 학생만
create or replace function public.game_progress_list(p_pin text, p_room text default null)
returns table(name text, items int, quizzes int, last_room text, updated_at timestamptz)
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not game_teacher_ok(p_pin) then raise exception '선생님 PIN이 맞지 않아요'; end if;
  return query
    select g.name,
           (select count(*) from jsonb_object_keys(case when jsonb_typeof(g.prog->'items')='object' then g.prog->'items' else '{}'::jsonb end))::int,
           (select count(*) from jsonb_each(case when jsonb_typeof(g.prog->'quiz')='object' then g.prog->'quiz' else '{}'::jsonb end) q where q.value = 'true'::jsonb)::int,
           g.last_room, g.updated_at
      from game_progress g
     where p_room is null or p_room = '' or g.last_room = p_room
     order by g.updated_at desc
     limit 500;
end $$;

-- 선생님: 학생이 비밀번호를 잊었을 때 새 비밀번호로 바꿔 주기
create or replace function public.game_reset_pw(p_pin text, p_name text, p_new_pw text)
returns void language plpgsql security definer set search_path = public, extensions as $$
begin
  if not game_teacher_ok(p_pin) then raise exception '선생님 PIN이 맞지 않아요'; end if;
  if p_new_pw is null or p_new_pw !~ '^[0-9]{4}$' then raise exception '새 비밀번호는 숫자 4자리예요'; end if;
  update game_progress set pw_hash = crypt(p_new_pw, gen_salt('bf')) where name = p_name;
  if not found then raise exception '그 이름의 학생이 없어요'; end if;
end $$;

revoke all on function public.game_teacher_ok(text) from public, anon, authenticated;
grant execute on function public.game_load(text, text) to anon, authenticated;
grant execute on function public.game_save(text, text, jsonb, jsonb, text) to anon, authenticated;
grant execute on function public.game_progress_list(text, text) to anon, authenticated;
grant execute on function public.game_reset_pw(text, text, text) to anon, authenticated;
