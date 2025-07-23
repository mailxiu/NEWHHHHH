/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.TableName;
/*    */ import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
@TableName("role_permission")
/*    */ public class RolePermission
        /*    */ implements Serializable {
    /*    */   private static final long serialVersionUID = 1L;
    /*    */   private Integer roleId;
    /*    */   private Integer permissionId;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.RolePermission)) return false;
        com.bss.entity.RolePermission other = (com.bss.entity.RolePermission) o;
        if (!other.canEqual(this)) return false;
        Object this$roleId = getRoleId(), other$roleId = other.getRoleId();
        if (!Objects.equals(this$roleId, other$roleId)) return false;
        Object this$permissionId = getPermissionId(), other$permissionId = other.getPermissionId();
        return !(!Objects.equals(this$permissionId, other$permissionId));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.RolePermission;
    }



    public String toString() {
        return "RolePermission(roleId=" + getRoleId() + ", permissionId=" + getPermissionId() + ")";
    }

    /*    */
    public Integer getRoleId() {
        /* 16 */
        return this.roleId;
        /*    */
    }

    /*    */
    /*    */
    public void setRoleId(Integer roleId) {
        /* 14 */
        this.roleId = roleId;
    }

    public Integer getPermissionId() {
        /* 18 */
        return this.permissionId;
        /*    */
    }

    public void setPermissionId(Integer permissionId) {
        this.permissionId = permissionId;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\RolePermission.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */