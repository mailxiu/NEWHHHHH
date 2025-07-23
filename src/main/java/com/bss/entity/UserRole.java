/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.TableName;
/*    */ import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
@TableName("user_role")
/*    */ public class UserRole
        /*    */ implements Serializable {
    /*    */   private static final long serialVersionUID = 1L;
    /*    */   private Integer userId;
    /*    */   private Integer roleId;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.UserRole)) return false;
        com.bss.entity.UserRole other = (com.bss.entity.UserRole) o;
        if (!other.canEqual(this)) return false;
        Object this$userId = getUserId(), other$userId = other.getUserId();
        if (!Objects.equals(this$userId, other$userId)) return false;
        Object this$roleId = getRoleId(), other$roleId = other.getRoleId();
        return !(!Objects.equals(this$roleId, other$roleId));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.UserRole;
    }


    public String toString() {
        return "UserRole(userId=" + getUserId() + ", roleId=" + getRoleId() + ")";
    }

    /*    */
    public Integer getUserId() {
        /* 16 */
        return this.userId;
        /*    */
    }

    /*    */
    /*    */
    public void setUserId(Integer userId) {
        /* 14 */
        this.userId = userId;
    }

    public Integer getRoleId() {
        /* 18 */
        return this.roleId;
        /*    */
    }

    public void setRoleId(Integer roleId) {
        this.roleId = roleId;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\UserRole.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */