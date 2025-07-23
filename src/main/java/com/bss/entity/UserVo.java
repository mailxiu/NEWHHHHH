/*    */
package com.bss.entity;

import com.baomidou.mybatisplus.annotation.TableName;

import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
/*    */
@TableName("user")
/*    */ public class UserVo implements Serializable {
    /*    */   private static final long serialVersionUID = 1L;
    /*    */   private String username;
    /*    */   private String password;
    /*    */   private String name;
    /*    */   private String appid;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.UserVo)) return false;
        com.bss.entity.UserVo other = (com.bss.entity.UserVo) o;
        if (!other.canEqual(this)) return false;
        Object this$username = getUsername(), other$username = other.getUsername();
        if (!Objects.equals(this$username, other$username)) return false;
        Object this$password = getPassword(), other$password = other.getPassword();
        if (!Objects.equals(this$password, other$password)) return false;
        Object this$name = getName(), other$name = other.getName();
        if (!Objects.equals(this$name, other$name)) return false;
        Object this$appid = getAppid(), other$appid = other.getAppid();
        return !(!Objects.equals(this$appid, other$appid));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.UserVo;
    }


    public String toString() {
        return "UserVo(username=" + getUsername() + ", password=" + getPassword() + ", name=" + getName() + ", appid=" + getAppid() + ")";
    }

    /*    */
    /*    */
    public String getUsername() {
        /* 15 */
        return this.username;
        /*    */
    }

    /*    */
    /* 12 */
    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        /* 17 */
        return this.password;
        /*    */
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getName() {
        /* 19 */
        return this.name;
        /*    */
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getAppid() {
        /* 21 */
        return this.appid;
        /*    */
    }

    public void setAppid(String appid) {
        this.appid = appid;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\UserVo.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */