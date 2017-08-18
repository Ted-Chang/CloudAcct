drop table if exists user;
create table user (
  user_id integer primary key autoincrement,
  username text not null,
  email text not null,
  pw_hash text not null
);

drop table if exists project;
create table project (
  project_id integer primary key autoincrement,
  project_name text not null,
  owner_id integer not null,
  company_name text not null,
  tax_id text not null,
  bank_name text,
  bank_account text,
  company_address text
);
