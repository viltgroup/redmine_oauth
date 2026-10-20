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
    # ApplicationController patch
    module ApplicationControllerPatch
      ################################################################################################################
      # Overridden methods

      # The token check. user_setup is the before_action that settles User.current, so overriding it rather than
      # adding a callback reaches every controller, whenever it was loaded.
      def user_setup
        super
        return if !RedmineOauth.token_check? || api_request? || User.current.anonymous? || oauth_session_alive?

        logout_user
        flash[:error] = l(:error_session_expired)
        require_login
      end

      # Core resets the session on every login. A provider session of the same user is carried across, so that
      # ending an impersonation, say, does not log the administrator out.
      def logged_user=(user)
        oauth_session_id = session[:oauth_session_id] if user.is_a?(User)
        oauth_login = session[:oauth_login]
        super
        return unless oauth_session_id && OauthSession.exists?(id: oauth_session_id, user_id: user.id)

        session[:oauth_session_id] = oauth_session_id
        session[:oauth_login] = oauth_login
      end

      private

      def oauth_session_alive?
        # While impersonating, the session is still the administrator's
        user_id = session[:true_user_id] || User.current.id
        oauth_session = session[:oauth_session_id] && OauthSession.find_by(id: session[:oauth_session_id],
                                                                             user_id: user_id)
        return oauth_session.alive? if oauth_session

        # No provider session behind it. Fine for a password login, but not for a session that OAuth started before
        # the check was switched on, nor for an SSO forced account, which got in some other way (autologin)
        session[:oauth_login].blank? && !RedmineOauth.sso_forced_user?(User.find_by(id: user_id))
      end
    end
  end
end

ApplicationController.prepend RedmineOauth::Patches::ApplicationControllerPatch
