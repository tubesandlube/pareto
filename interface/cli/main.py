import curses
from curses import KEY_RIGHT, KEY_LEFT, KEY_UP, KEY_DOWN

def initialize():
    curses.initscr()
    win = curses.newwin(24, 80, 0, 0)
    win.keypad(1)
    curses.noecho()
    curses.curs_set(0)
    win.border(0)
    win.nodelay(1)

    key = KEY_RIGHT
    git_handle = []

    win.addstr(0, 2, ' Login ')
    win.addstr(0, 36, ' PARETO ')
    win.addstr(12, 31, ' GitHub Username: ')
    curses.echo()
    while key != 27 and key != ord('\n'):
        y,x=curses.getsyx()
        #win.addstr(12, 48+len(git_handle), curses.A_REVERSE)
        event = win.getch()
        if event != -1:
            prevKey = key
            try:
                git_handle.append(chr(prevKey))
            except:
                # not a printable ascii character
                pass
            key = event
            curses.setsyx(y,x+1)
            curses.doupdate()

    #if key == 27:
    #    curses.endwin()
    curses.endwin()
    print "git handle:", "".join(git_handle)

def draw_level(level):
    score = 0
    # TODO
    #    win.addstr(0, 2, 'Level: ' + 
    #    win.addstr(0, 2, 'Score: ' + str(score) + ' ')
    return True

if __name__ == "__main__":
    initialize()

