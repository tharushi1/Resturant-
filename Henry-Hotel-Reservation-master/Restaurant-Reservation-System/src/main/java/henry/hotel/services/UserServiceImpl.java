package henry.hotel.services;

import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import henry.hotel.entity.Role;
import henry.hotel.entity.User;
import henry.hotel.repository.RoleRep;
import henry.hotel.repository.UserRep;
import henry.hotel.temp.CurrentUser;

@Service
public class UserServiceImpl implements UserService {
	private final UserRep userRepository;
	private final RoleRep roleRepository;
	private final BCryptPasswordEncoder passwordEncoder;

	@Autowired
	public UserServiceImpl(UserRep userRepository, RoleRep roleRepository,
			@Lazy BCryptPasswordEncoder passwordEncoder) {
		this.userRepository = userRepository;
		this.roleRepository = roleRepository;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	@Transactional
	public User findUserByEmail(String email) {
		return userRepository.findByEmail(email);
	}

	@Override
	@Transactional
	public void saveUser(CurrentUser currentUser) {
		User user = new User();
		user.setPassword(passwordEncoder.encode(currentUser.getPassword()));
		user.setUsername(currentUser.getUsername());
		user.setEmail(currentUser.getEmail());
		user.setRoles(Arrays.asList(roleRepository.findByName("ROLE_EMPLOYEE")));
		userRepository.save(user);
	}

	@Override
	@Transactional
	public int getLoggedUserId() {
		User user = userRepository.findByUsername(loggedUserEmail());
		return user.getId();
	}

	@Override
	@Transactional
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		User user = userRepository.findByEmail(email);
		if (user == null) {
			throw new UsernameNotFoundException("Invalid username or password.");
		}
		return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
				mapRolesToAuthorities(user.getRoles()));
	}

	private Collection<? extends GrantedAuthority> mapRolesToAuthorities(Collection<Role> roles) {
		return roles.stream().map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toList());
	}

	private String loggedUserEmail() {
		Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		if (principal instanceof UserDetails) {
			return ((UserDetails) principal).getUsername();
		}
		return principal.toString();
	}
}
