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

module RedmineOauth
  module Patches
    # User patch
    module UserPatch
      ################################################################################################################
      # Overridden methods

      # A password is no answer for an SSO forced account. AccountController#login already redirects those to the
      # provider, but the REST API's HTTP Basic authentication never passes through it, so the rule belongs here too.
      def check_password?(clear_password)
        return false if RedmineOauth.sso_forced_user?(self)

        super
      end
    end
  end
end

User.prepend RedmineOauth::Patches::UserPatch
