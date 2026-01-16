local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Footprint script for identifying Gogs-like Git web services and estimating CVE-2025-8110 status.
Always outputs one of: possible / inconclusive / not_vulnerable / not_detected, followed by evidence.
Non-exploit and safe reconnaissance.
]]

author = "WIKI Security Lab"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- Web services only (HTTP/HTTPS)
portrule = function(host, port)
  if shortport.http(host, port) then return true end
  if shortport.ssl(host, port) then return true end
  return false
end

local function lower(s) return s and string.lower(s) or "" end
local function truncate(s, n) if not s then return nil end return (#s <= n) and s or s:sub(1, n) end
local function safe_header(h, key) if not h then return nil end return h[key] or h[lower(key)] end

local function extract_title(body)
  if not body then return nil end
  local t = body:match("<title[^>]*>(.-)</title>")
  if not t then return nil end
  t = t:gsub("%s+", " "):gsub("^%s+", ""):gsub("%s+$", "")
  return truncate(t, 120)
end

local function extract_meta_hint(body)
  if not body then return nil end

  local gen = body:match('<meta%s+name=["\']generator["\']%s+content=["\']([^"\']+)["\']')
  if gen then
    gen = gen:gsub("%s+", " "):gsub("^%s+", ""):gsub("%s+$", "")
    return truncate(gen, 120), "generator"
  end

  local author = body:match('<meta%s+name=["\']author["\']%s+content=["\']([^"\']+)["\']')
  if author then
    author = author:gsub("%s+", " "):gsub("^%s+", ""):gsub("%s+$", "")
    return truncate(author, 120), "author"
  end

  return nil
end

local function parse_semver(v)
  if not v then return nil end
  local maj, min, pat = v:match("^(%d+)%.(%d+)%.(%d+)$")
  if not maj then return nil end
  return tonumber(maj), tonumber(min), tonumber(pat)
end

local function semver_le(a, b)
  local a1,a2,a3 = parse_semver(a)
  local b1,b2,b3 = parse_semver(b)
  if not a1 or not b1 then return nil end
  if a1 ~= b1 then return a1 < b1 end
  if a2 ~= b2 then return a2 < b2 end
  return a3 <= b3
end

local function has_cookie(set_cookie_value, needle)
  if not set_cookie_value then return false end
  return lower(set_cookie_value):find(lower(needle), 1, true) ~= nil
end

local function identify_product(body, title, meta_hint, set_cookie)
  local b = lower(body or "")
  local t = lower(title or "")
  local m = lower(meta_hint or "")
  local c = lower(set_cookie or "")

  if m:find("gogs", 1, true) or t:find("gogs", 1, true) then return "Gogs" end
  if m:find("gitea", 1, true) or t:find("gitea", 1, true) then return "Gitea" end
  if m:find("forgejo", 1, true) or t:find("forgejo", 1, true) then return "Forgejo" end

  if c:find("i_like_gogs=", 1, true) then return "Gogs" end

  if b:find("gogs", 1, true) or b:find("i_like_gogs", 1, true) then return "Gogs-like" end
  if b:find("gitea", 1, true) then return "Gogs-like" end
  if b:find("forgejo", 1, true) then return "Gogs-like" end

  return nil
end

-- Strong-but-fast version extraction from HTML/JS/asset hints
local function extract_version_hints(body)
  if not body then return nil end
  local patterns = {
    -- explicit
    "[Gg]ogs%s*[Vv]ersion%s*[:=]%s*v?([0-9]+%.[0-9]+%.[0-9]+)",
    "[Gg]ogs%s+v([0-9]+%.[0-9]+%.[0-9]+)",
    "Powered%s+by%s+[Gg]ogs%s*v?([0-9]+%.[0-9]+%.[0-9]+)",

    -- near keywords (bounded window)
    "[Gg]ogs[^<>\n\r]{0,200}v?([0-9]+%.[0-9]+%.[0-9]+)",
    "[Gg]ogs[^<>\n\r]{0,200}[Vv]ersion%s*[:=]%s*v?([0-9]+%.[0-9]+%.[0-9]+)",
    "[Vv]ersion%s*[:=]%s*v?([0-9]+%.[0-9]+%.[0-9]+)[^<>\n\r]{0,200}[Gg]ogs",

    -- data attributes / JS tokens
    "data%-version%s*=%s*['\"]v?([0-9]+%.[0-9]+%.[0-9]+)['\"]",
    "appVersion%s*[:=]%s*['\"]v?([0-9]+%.[0-9]+%.[0-9]+)['\"]",
    "version%s*[:=]%s*['\"]v?([0-9]+%.[0-9]+%.[0-9]+)['\"]",

    -- asset querystring hints
    "[%?&]v=([0-9]+%.[0-9]+%.[0-9]+)",
    "[%?&]ver=([0-9]+%.[0-9]+%.[0-9]+)",
  }

  for _, p in ipairs(patterns) do
    local v = body:match(p)
    if v then return v end
  end
  return nil
end

-- Optional 2nd request: login page (fast, higher chance to include assets/footer hints)
local function try_login_page_for_version(host, port, opts_base, probe_timeout, why)
  local opts = { timeout = probe_timeout, header = opts_base.header, ssl = opts_base.ssl }

  local paths = {
    "/user/login",
    "/user/login?redirect_to=%2fapi%2fv1%2fswagger"
  }

  for _, path in ipairs(paths) do
    local r = http.get(host, port, path, opts)
    if r and r.status and r.body and (r.status == 200 or r.status == 302 or r.status == 303) then
	  if not stdnse.contains(why, ("login_page=%s"):format(path)) then
	    table.insert(why,("login_page=%s"):format(path))
	  end

      local v = extract_version_hints(r.body)
      if v then
        table.insert(why, ("version_src=%s"):format(path))
        return v
      end

      if r.header then
        local loc = safe_header(r.header, "location")
        if loc then
          local v2 = loc:match("([0-9]+%.[0-9]+%.[0-9]+)")
          if v2 then
            table.insert(why, ("version_src=redirect:%s"):format(path))
            return v2
          end
        end
      end

      table.insert(why, ("login_probe=%s_no_version"):format(path))
      return nil
    elseif r and r.status then
      table.insert(why, ("login_probe=%s_%d"):format(path, r.status))
    end
  end

  return nil
end

action = function(host, port)
  local base_path = stdnse.get_script_args("http-gogs-cve2025-8110-footprint.path") or "/"
  local timeout = tonumber(stdnse.get_script_args("http-gogs-cve2025-8110-footprint.timeout")) or 4000
  local probe_timeout = tonumber(stdnse.get_script_args("http-gogs-cve2025-8110-footprint.probe_timeout")) or 1200
  local max_body = tonumber(stdnse.get_script_args("http-gogs-cve2025-8110-footprint.max_body")) or 32768

  local opts = { timeout = timeout, header = {} }
  local vhost = stdnse.get_script_args("http.host")
  if vhost then opts.header["Host"] = vhost end
  if shortport.ssl(host, port) then opts.ssl = true end

  local status = "inconclusive"
  local product = nil
  local detected_version = nil
  local affected_max = "0.13.3"
  local why = {}

  local r = http.get(host, port, base_path, opts)
  if not r or not r.status then
    table.insert(why, "no_http_response")
    local out = {}
    table.insert(out, ("CVE-2025-8110: %s [unknown] affected<=%s"):format(status, affected_max))
    table.insert(out, ("Evidence: %s"):format(table.concat(why, "; ")))
    return stdnse.format_output(true, out)
  end

  local server = (r.header and safe_header(r.header, "server")) or nil
  local set_cookie = (r.header and safe_header(r.header, "set-cookie")) or nil

  table.insert(why, ("path=%s"):format(base_path))
  table.insert(why, ("http=%d"):format(r.status))
  if server then table.insert(why, ("server=%s"):format(truncate(server, 60))) end

  local body = r.body or ""
  if #body > max_body then body = body:sub(1, max_body) end

  local title = extract_title(body)
  if title then table.insert(why, ('title="%s"'):format(title)) end

  local meta_hint, meta_kind = extract_meta_hint(body)
  if meta_hint and meta_kind then
    table.insert(why, ("meta_%s=%s"):format(meta_kind, meta_hint))
  end

  if set_cookie and has_cookie(set_cookie, "i_like_gogs=") then
    table.insert(why, "cookie=i_like_gogs")
  end

  product = identify_product(body, title, meta_hint, set_cookie)

  if not product then
    status = "not_detected"
    table.insert(why, "no_gogs_indicators")
  else
    if product == "Gitea" or product == "Forgejo" then
      status = "not_detected"
      table.insert(why, ("product=%s_not_applicable"):format(lower(product)))
    else
      -- 1) main page
      detected_version = extract_version_hints(body)
      if detected_version then
        table.insert(why, "version_src=main")
      end

      -- 2) login page (only when strong Gogs indicators exist and version not found)
      local strong_gogs =
        (product == "Gogs") or
        (set_cookie and has_cookie(set_cookie, "i_like_gogs=")) or
        (meta_hint and lower(meta_hint) == "gogs")

      if (not detected_version) and strong_gogs then
        table.insert(why, "login_probe=on")
        detected_version = try_login_page_for_version(host, port, opts, probe_timeout, why)
      else
        if not detected_version then table.insert(why, "login_probe=skipped") end
      end

      if detected_version then
        local le = semver_le(detected_version, affected_max)
        if le == true then
          status = "possible"
          table.insert(why, "affected_version")
        elseif le == false then
          status = "not_vulnerable"
          table.insert(why, "newer_than_affected")
        else
          status = "inconclusive"
          table.insert(why, "version_unparsable")
        end
      else
        status = "inconclusive"
        table.insert(why, "version_not_exposed")
      end
    end
  end

  local out = {}
  local pv = product or "unknown"
  local vv = detected_version and (" ver=" .. detected_version) or ""
  table.insert(out, ("CVE-2025-8110: %s [%s%s] affected<=%s"):format(status, pv, vv, affected_max))
  table.insert(out, ("Evidence: %s"):format(table.concat(why, "; ")))
  return stdnse.format_output(true, out)
end
