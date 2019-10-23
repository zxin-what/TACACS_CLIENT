package com.venustech.tacacs;
import com.venustech.tacacs.protocol.enums.TACACS_PLUS;

import java.io.Console;

/**
 * This class handles interactive authentication requests; 
 * 
 * @author Chris.Janicki@augur.com
 * Copyright 2016 Augur Systems, Inc.  All rights reserved.
 */
public abstract class UserInterface {

	protected String username=null;

	/**
	 *
	 * @param prompt
	 * @param noEcho
	 * @param getWhat
	 * @return
	 */
	public abstract String getUserInput(String prompt, boolean noEcho, TACACS_PLUS.AUTHEN.STATUS getWhat);


	/**
	 *
	 * @return
	 */
	public final String getUsername() { return username; }
	
	

	/**
	 * 控制台输入
	 * @return
	 */
	public static final UserInterface getConsoleInstance() {

		return new UserInterface() {
			@Override
			public String getUserInput(String prompt, boolean noEcho, TACACS_PLUS.AUTHEN.STATUS getWhat) {
				Console console = System.console();
				if (console == null) { System.out.println("No console available!"); return null; }
				System.out.println();
				System.out.print(prompt);
				String input = noEcho? new String(console.readPassword()) : console.readLine();
				if (getWhat == TACACS_PLUS.AUTHEN.STATUS.GETUSER) { this.username = input; }
				return input;
			}
		};
	}

	
	
}
