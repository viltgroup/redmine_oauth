# frozen_string_literal: true

# Redmine plugin OAuth
#
# Karel Pičman <karel.picman@kontron.com>
#
# This file is part of Redmine OAuth plugin.
#
# Redmine OAuth plugin is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# Redmine OAuth plugin is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even
# the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with Redmine OAuth plugin. If not, see
# <https://www.gnu.org/licenses/>.

# Main module
module RedmineOauth
  # Settings
  class << self
    def hide_login_form?
      value = Setting.plugin_redmine_oauth['hide_login_form']
      value.to_i.positive? || value == 'true'
    end

    def login_headers?
      value = Setting.plugin_redmine_oauth['login_headers']
      value.to_i.positive? || value == 'true'
    end

    # Separator shown above the standard login form, blank when headers are off.
    def login_header_form
      login_headers? ? Setting.plugin_redmine_oauth['login_header_form'].to_s.strip : ''
    end

    # Separator shown above the OAuth buttons, blank when headers are off.
    def login_header_oauth
      login_headers? ? Setting.plugin_redmine_oauth['login_header_oauth'].to_s.strip : ''
    end

    def self_registration
      Setting.plugin_redmine_oauth['self_registration'].to_i
    end

    # Comma-separated domains for self_registration mode 4 (auto-activate if email domain matches).
    def self_registration_domains_list
      domains_list('self_registration_domains')
    end

    def self_registration_domain_auto_activate?(email)
      return false if self_registration != 4

      domain_listed?(email, self_registration_domains_list)
    end

    # Comma-separated domains whose accounts may only authenticate through an OAuth provider.
    def sso_forced_domains_list
      domains_list('sso_forced_domains')
    end

    # Logins kept out of the forced SSO, so there is still a way in while the provider is unreachable.
    def sso_forced_exempt_logins_list
      Setting.plugin_redmine_oauth['sso_forced_exempt_logins'].to_s.split(',')
             .map { |s| s.strip.downcase }.compact_blank
    end

    def sso_forced_email?(email)
      domain_listed?(email, sso_forced_domains_list)
    end

    def sso_forced_user?(user)
      return false if user.nil? || sso_forced_exempt_logins_list.include?(user.login.to_s.downcase)

      sso_forced_email?(user.mail)
    end

    # Decides on a login name typed into the login form. An unknown account is still decidable when
    # an email address was typed, which is what the on-the-fly LDAP registration gets asked with.
    def sso_forced_login?(login)
      login = login.to_s.strip
      return false if login.blank? || sso_forced_exempt_logins_list.include?(login.downcase)

      user = User.find_by_login(login)
      return sso_forced_email?(user.mail) if user

      login.include?('@') && sso_forced_email?(login)
    end

    def update_login?
      value = Setting.plugin_redmine_oauth['update_login']
      value.to_i.positive? || value == 'true'
    end

    def update_email?
      value = Setting.plugin_redmine_oauth['update_email']
      value.to_i.positive? || value == 'true'
    end

    def update_firstname?
      value = Setting.plugin_redmine_oauth['update_firstname']
      value.to_i.positive? || value == 'true'
    end

    def update_lastname?
      value = Setting.plugin_redmine_oauth['update_lastname']
      value.to_i.positive? || value == 'true'
    end

    def oauth_logout?
      value = Setting.plugin_redmine_oauth['oauth_logout']
      value.to_i.positive? || value == 'true'
    end

    def oauth_login?
      value = Setting.plugin_redmine_oauth['oauth_login']
      value.to_i.positive? || value == 'true'
    end

    def oauth_only_login?
      value = Setting.plugin_redmine_oauth['oauth_only_login']
      value.to_i.positive? || value == 'true'
    end

    private

    def domains_list(setting)
      Setting.plugin_redmine_oauth[setting].to_s.split(',')
             .map { |s| s.strip.downcase.delete_prefix('@') }.compact_blank
    end

    # True when email's domain exactly matches or is a subdomain of a listed domain.
    def domain_listed?(email, domains)
      return false if domains.empty?

      email_domain = email.to_s.downcase.split('@', 2).last
      return false if email_domain.blank?

      domains.any? { |d| email_domain == d || email_domain.end_with?(".#{d}") }
    end
  end
end

# Hooks
require File.expand_path('redmine_oauth/hooks/controllers/account_controller_hooks', __dir__)
require File.expand_path('redmine_oauth/hooks/views/base_view_hooks', __dir__)
require File.expand_path('redmine_oauth/hooks/views/login_view_hooks', __dir__)

# Patches
require File.expand_path('redmine_oauth/patches/settings_controller_patch', __dir__)
require File.expand_path('redmine_oauth/patches/account_controller_patch', __dir__)
require File.expand_path('redmine_oauth/patches/user_patch', __dir__)
require File.expand_path('../lib/redmine_oauth/patches/sudo_mode_controller_patch', __dir__)
