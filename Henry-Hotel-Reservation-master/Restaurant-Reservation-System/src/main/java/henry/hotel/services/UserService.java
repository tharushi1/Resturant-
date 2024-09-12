package henry.hotel.services;

import henry.hotel.entity.User;
import henry.hotel.temp.CurrentUser;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService extends UserDetailsService {
	User findUserByEmail(String email);

	void saveUser(CurrentUser currentUser);

	int getLoggedUserId();
}
