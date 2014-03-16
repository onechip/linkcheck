
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <map>
#include <sstream>
#include <iostream>

#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h> 
#include <unistd.h>
#include <utime.h>

#include <openssl/sha.h>


/* Copyright 2014 Chris Studholme.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


static const unsigned DIFF_BUFSIZE = 1024*1024;

static off_t opt_min_filesize = 1;
static bool opt_report_links = false;
static bool opt_make_links = false;
static bool opt_use_digest = true;


static void report_sbuf(std::ostream& out, const struct stat& sbuf) {
    out << "  "
        << sbuf.st_dev << ',' << sbuf.st_ino << ','
        << sbuf.st_mode << ','
        << sbuf.st_nlink << ','
        << sbuf.st_uid << ',' << sbuf.st_gid << ','
        << sbuf.st_rdev << ','
        << sbuf.st_size << ',' << sbuf.st_blksize << ',' << sbuf.st_blocks << ','
        << sbuf.st_atime << ',' << sbuf.st_mtime << ',' << sbuf.st_ctime
        << std::endl;
}

static bool equal_sbuf(const struct stat& s1, const struct stat& s2) {
    // NOTE: I don't think atime should be included here!
    return (s1.st_dev == s2.st_dev &&
            s1.st_ino == s2.st_ino &&
            s1.st_mode == s2.st_mode &&
            s1.st_nlink == s2.st_nlink &&
            s1.st_uid == s2.st_uid &&
            s1.st_gid == s2.st_gid &&
            s1.st_rdev == s2.st_rdev &&
            s1.st_size == s2.st_size &&
            s1.st_blksize == s2.st_blksize &&
            s1.st_blocks == s2.st_blocks &&
            s1.st_atime == s2.st_atime &&
            s1.st_mtime == s2.st_mtime &&
            s1.st_ctime == s2.st_ctime);
}

static int compare_file(int fd1, int fd2) {
    if (lseek(fd1,0,SEEK_SET) != 0) {
        std::cerr << "linkcheck: failed to seek" << std::endl;
        return -1;
    }
    if (lseek(fd2,0,SEEK_SET) != 0) {
        std::cerr << "linkcheck: failed to seek" << std::endl;
        return 1;
    }
  
    unsigned char b1[DIFF_BUFSIZE];
    unsigned char b2[DIFF_BUFSIZE];
    ssize_t s1,s2;
  
    do {
        s1 = read(fd1,b1,sizeof(b1));
        s2 = read(fd2,b2,sizeof(b2));
        if (s1 < s2)
            return -1;
        else if (s1 > s2)
            return 1;
        int c = memcmp(b1,b2,s1);
        if (c != 0)
            return c;
    } while (s1 > 0);

    return 0;
}

static std::basic_string<unsigned char> compute_digest(int fd, off_t total) {
    std::basic_string<unsigned char> result;
    if (lseek(fd,0,SEEK_SET) != 0) {
        std::cerr << "linkcheck: failed to seek" << std::endl;
        return result;
    }

    SHA512_CTX ctx;
    int r = SHA512_Init(&ctx);
    assert(r == 1);

    for (;;) {
        unsigned char buf[DIFF_BUFSIZE];
        ssize_t n = read(fd,buf,sizeof(buf));
        if (n <= 0) break;

        r = SHA512_Update(&ctx, buf, n);
        assert(r == 1);
        total -= n;
    }


    if (total != 0) {
        std::cerr << "linkcheck: failed to hash" << std::endl;
        return result;
    }

    result.resize(SHA512_DIGEST_LENGTH);
    r = SHA512_Final(&result[0], &ctx);
    assert(r == 1);
    return result;
}


/* Links associated with specific inode.
 */
class inode_links {
private:
    struct stat sbuf;
    int fd;
    struct flock lock;

    typedef std::vector<std::string> links_type;
    links_type links;

    std::basic_string<unsigned char> digest;

public:
    inode_links() : fd(-1) {}

    ~inode_links() {
        close();
    }

    void close() {
        if (fd != -1) {
            ::close(fd);
            fd = -1;
        }
    }

    bool open(bool use_digest) {
        if (fd != -1)
            return true;
        assert(!links.empty());
        fd = ::open(links.front().c_str(),O_RDONLY);
        if (fd == -1)
            return false;
        // lock file
        lock.l_type = F_RDLCK;
        lock.l_whence = SEEK_SET;
        lock.l_start = 0;
        lock.l_len = 0;
        if (fcntl(fd,F_SETLKW,&lock) != 0) {
            ::close(fd);
            fd = -1;
            return false;
        }
        if (use_digest) {
            std::cout << "digest: (" << sbuf.st_size << ") "
                      << links.front() << std::endl;
            digest = compute_digest(fd,sbuf.st_size);
        }
        return true;
    }

    inline bool empty() const {
        return links.empty();
    }

    inline links_type::size_type size() const {
        return links.size();
    }

    inline const char* name() const {
        return links.front().c_str();
    }

    inline bool missing_links() const {
        return links.size() != sbuf.st_nlink;
    }

    inline bool has_digest() const {
        return !digest.empty();
    }

    void report(std::ostream& out = std::cout) const {
        out << "linked:";
        for (links_type::const_iterator
                 it = links.begin(); it != links.end(); ++it)
            out << " '" << *it << "'";
        out << std::endl;
    }

    void add_link(const char* name, const struct stat& sbuf) {
        if (links.empty())
            memcpy(&this->sbuf, &sbuf, sizeof(struct stat));
        else if (!equal_sbuf(this->sbuf,sbuf)) {
            std::cerr << "linkcheck: linked files have non-matching stat"
                      << std::endl;
            report_sbuf(std::cerr,this->sbuf);
            report_sbuf(std::cerr,sbuf);
        }
        links.push_back(name);
    }

    static int compare(inode_links& f1, inode_links& f2) {
        if (f1.digest.empty() || f2.digest.empty())
            return compare_file(f1.fd,f2.fd);
        assert(f1.digest.size() == f2.digest.size());
        return f1.digest.compare(f2.digest);
    }

    // relink all files in src to this inode
    bool relink_from(inode_links& src) {
        if (sbuf.st_mtime > src.sbuf.st_mtime) {
            // reset mtime on this
            struct utimbuf ut;
            ut.modtime = src.sbuf.st_mtime;
            ut.actime = sbuf.st_atime > src.sbuf.st_atime ?
                sbuf.st_atime : src.sbuf.st_atime;
            if (utime(links.front().c_str(),&ut) != 0) {
                std::cerr << "linkcheck: utime failed on '"
                          << links.front() << "'" << std::endl;
                return false;
            }
        }
        
        for (links_type::const_reverse_iterator 
                 it = src.links.rbegin(); it != src.links.rend(); /*in body*/) {
            // create new link
            std::stringstream new_link_ss;
            new_link_ss << *it << ".link_to_inode_" << sbuf.st_ino;
            const std::string new_link = new_link_ss.str();
            if (link(links.front().c_str(),new_link.c_str()) != 0) {
                std::cerr << "linkcheck: failed to create link '"
                          << new_link << "'" << std::endl;
                return false;
            }
            // rename
            if (rename(new_link.c_str(),it->c_str()) != 0) {
                std::cerr << "linkcheck: failed to rename '"
                          << new_link << "'" << std::endl;
                if (unlink(new_link.c_str()) != 0)
                    std::cerr << "linkcheck: failed to unlink '"
                              << new_link << "'" << std::endl;
                return false;
            }
            std::cout << "link: '" << links.front()
                      << "' <- '" << *it << "'" << std::endl;
            links.push_back(*it);
            ++it;
            src.links.pop_back();
        }

        return true;
    }

    static void link_files(inode_links& f1, inode_links& f2) {
        assert(!f1.empty() && !f2.empty());
        
        // re-stat files
        if (fstat(f1.fd,&f1.sbuf) != 0) {
            std::cerr << "linkcheck: failed to stat '"
                      << f1.links.front() << "'" << std::endl;
            return;
        }
        if (fstat(f2.fd,&f2.sbuf) != 0) {
            std::cerr << "linkcheck: failed to stat '"
                      << f2.links.front() << "'" << std::endl;
            return;
        }

        if (f1.sbuf.st_mode != f2.sbuf.st_mode ||
            f1.sbuf.st_uid != f2.sbuf.st_uid ||
            f1.sbuf.st_gid != f2.sbuf.st_gid ||
            f1.sbuf.st_size != f2.sbuf.st_size) {
            std::cout << "permissions differ: '"
                      << f1.links.front() << "' '"
                      << f2.links.front() << "'" << std::endl;
            return;
        }

        if (f1.missing_links() && f2.missing_links()) { 
            std::cout << "missing links: '"
                      << f1.links.front() << "' '"
                      << f2.links.front() << "'" << std::endl;
            return;
        }  

        if (f1.missing_links())
            f1.relink_from(f2);
        else if (f2.missing_links())
            f2.relink_from(f1);
        else if (f1.sbuf.st_nlink > f2.sbuf.st_nlink)
            f1.relink_from(f2);
        else if (f1.sbuf.st_nlink < f2.sbuf.st_nlink)
            f2.relink_from(f1);
        else if (f1.sbuf.st_mtime > f2.sbuf.st_mtime)
            f2.relink_from(f1);
        else
            f1.relink_from(f2);
    }
};


/* Files of a specific size.
 */
typedef std::pair<dev_t,ino_t> inode_id;
typedef std::map<inode_id,inode_links> size_map_type;

static void process_size(size_map_type& same_size, bool use_digest) {
    if (opt_report_links) {
        // report on files that are already linked
        for (size_map_type::iterator
                 it = same_size.begin(); it != same_size.end(); ++it)
            if (it->second.size() > 1)
                it->second.report();
    }

    if (same_size.size() <= 1)
        return;  // nothing to do

    if (same_size.size() < 4)
        use_digest = false;

    // check for non-linked identical files
    for (size_map_type::iterator
             it = same_size.begin(); it != same_size.end(); ++it) {
        if (it->second.empty())
            continue;
        if (!it->second.open(use_digest)) {
            std::cerr << "linkcheck: failed to open '"
                      << it->second.name() << "'" << std::endl;
            continue;
        }
        size_map_type::iterator jt = it;
        for (++jt; jt != same_size.end(); ++jt) {
            if (jt->second.empty())
                continue;
            if ((!it->second.has_digest() ||
                 !jt->second.has_digest()) &&
                !jt->second.open(use_digest)) {
                std::cerr << "linkcheck: failed to open '"
                          << jt->second.name() << "'" << std::endl;
                continue;
            }
            if (inode_links::compare(it->second,jt->second) == 0) {
                if (opt_make_links) {
                    if (!jt->second.open(use_digest)) {
                        std::cerr << "linkcheck: failed to open '"
                                  << jt->second.name() << "'" << std::endl;
                        continue;
                    }
                    inode_links::link_files(it->second,jt->second);
                }
                else
                    std::cout << "same: '"
                              << it->second.name() << "' '"
                              << jt->second.name() << "'" << std::endl;
            }
            jt->second.close();
        }
        it->second.close();
    }
}


/* All files scanned.  Key is file size.
 */
typedef std::map<off_t,size_map_type> all_files_type;

static void scan_dir(all_files_type& index, const char* name) {
    DIR* dir = opendir(name);
    if (dir == NULL) {
        std::cerr << "linkcheck: failed to open directory '"
                  << name << "'" << std::endl;
        return;
    }

    char* pathname = new char[strlen(name)+NAME_MAX+2];
    strcpy(pathname,name);
    strcat(pathname,"/");
    char* filename = strchr(pathname,0);

    struct dirent *ent;
    while ((ent=readdir(dir)) != NULL) {
        if (strcmp(ent->d_name,".") == 0 || strcmp(ent->d_name,"..") == 0)
            continue;  // ignore
        
        strcpy(filename,ent->d_name);
        struct stat sbuf;
        if (lstat(pathname,&sbuf) != 0)
            std::cerr << "linkcheck: failed to stat '"
                      << pathname << "'" << std::endl;
        
        else if (S_ISDIR(sbuf.st_mode))
            scan_dir(index,pathname);
        
        else if (S_ISREG(sbuf.st_mode))
            index[sbuf.st_size][std::make_pair(sbuf.st_dev,sbuf.st_ino)].
                add_link(pathname,sbuf);
    }

    delete[] pathname;
    closedir(dir);
}


static void usage() {
    std::cerr << std::endl;
    std::cerr << "Usage:" << std::endl;
    std::cerr << "  linkcheck [ options ] directory ..." << std::endl;
    std::cerr << std::endl;
    std::cerr << "  -m\tmake new links where needed" << std::endl;
    std::cerr << "  -r\treport existing links" << std::endl;
    std::cerr << "  -s\tdo not use SHA-512 optimization" << std::endl;
    std::cerr << "  -z #\tminimum file size (default is 1)" << std::endl;
    std::cerr << std::endl;
}


int main(int argc, char*argv[]) {

    --argc; ++argv;
    while (argc && argv[0][0] == '-') {
        if (argv[0][1] == '-') {
            --argc; ++argv;
            break;
        }      
        switch(argv[0][1]) {
        case 'r':
            opt_report_links = true;
            break;

        case 's':
            opt_use_digest = false;
            break;

        case 'z':
            if (argv[0][2])
                opt_min_filesize = atol(argv[0]+2);
            else {
                --argc; ++argv;
                if (!argc) {
                    usage();
                    return 1;
                }
                opt_min_filesize = atol(argv[0]);
            }
            if (opt_min_filesize < 0)
                opt_min_filesize = 0;
            std::cerr << "linkcheck: min filesize: "
                      << opt_min_filesize << std::endl;
            break;
            
        case 'm':
            opt_make_links = true;
            break;

        default:
            usage();
            return 1;
        }
        --argc; ++argv;
    }
  
    if (argc <= 0) {
        usage();
        return 1;
    }
  
    all_files_type index;
    for (int i = 0; i < argc; ++i)
        scan_dir(index,argv[i]);

    for (all_files_type::iterator
             it = index.begin(); it != index.end(); ++it) {
        if (it->first >= opt_min_filesize)
            process_size(it->second,
                         opt_use_digest && it->first >= 1024*1024);
    }
   
    return 0;
}
